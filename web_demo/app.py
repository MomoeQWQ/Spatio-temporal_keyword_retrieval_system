from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from functools import wraps
from typing import Dict, List

from flask import Flask, flash, redirect, render_template, request, session, url_for

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))

import sys

if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from ai_clients import make_gemini_llm
from config_loader import load_config as load_core_config
from online_demo.runtime_utils import http_post, stop_processes, start_csp_servers
from online_demo.user_management import (
    authenticate_user,
    create_or_update_group,
    create_or_update_user,
    list_users_public,
    load_user_db,
    save_user_db,
)
from secure_search import (
    combine_csp_responses,
    decrypt_matches,
    prepare_query_plan,
    prepare_query_plan_with_expansion,
    rank_results_by_priority,
    run_fx_hmac_verification,
)
from secure_search.indexing import load_index_artifacts
from web_demo.config_store import csp_endpoints, load_config, parse_ports_csv, ports_to_csv, save_config


@dataclass
class RuntimeState:
    csp_procs: List = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def running(self) -> bool:
        return any(p.poll() is None for p in self.csp_procs)

    def start_csp(self, cfg: Dict) -> None:
        with self.lock:
            if self.running():
                return
            if not os.path.exists(cfg["aui_path"]):
                raise FileNotFoundError(f"AUI path not found: {cfg['aui_path']}")
            self.csp_procs = start_csp_servers(
                cfg["csp_ports"],
                aui_path=cfg["aui_path"],
                user_db_path=cfg["user_db_path"],
            )

    def stop_csp(self) -> None:
        with self.lock:
            stop_processes(self.csp_procs)
            self.csp_procs = []


app = Flask(
    __name__,
    template_folder=os.path.join(THIS_DIR, "templates"),
    static_folder=os.path.join(THIS_DIR, "static"),
)
app.secret_key = os.environ.get("WEB_DEMO_SECRET", "st-vls-web-demo-secret")
runtime = RuntimeState()


def _current_cfg() -> Dict:
    return load_config()


def _is_logged_in() -> bool:
    return bool(session.get("user"))


def _is_admin() -> bool:
    return bool(session.get("admin_user"))


def require_user(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _is_logged_in():
            return redirect(url_for("index"))
        return f(*args, **kwargs)

    return wrapper


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _is_admin():
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)

    return wrapper


def _run_one_plan(plan, endpoints: List[str], auth_token: str, aui: dict, keys: tuple):
    responses = []
    for party_id, base in enumerate(endpoints):
        body = {
            "party_id": party_id,
            "tokens": plan.payloads[party_id],
            "security_param": plan.security_param,
            "auth_token": auth_token,
        }
        responses.append(http_post(base + "/eval", body))
    combined_vecs, combined_proofs = combine_csp_responses(plan, responses, aui)
    _, hits = decrypt_matches(plan, combined_vecs, aui, keys)
    ok_verify = run_fx_hmac_verification(plan, combined_vecs, combined_proofs, aui, keys)
    return ok_verify, hits


def _source_label(base_hit: bool, source_hits: int) -> str:
    if source_hits <= 0:
        return "none"
    if base_hit and source_hits == 1:
        return "base"
    if base_hit:
        return f"base+{source_hits - 1}exp"
    return f"{source_hits}exp"


@app.route("/")
def index():
    cfg = _current_cfg()
    if not _is_logged_in():
        return render_template("user_login.html", cfg=cfg, csp_running=runtime.running())
    return redirect(url_for("search_page"))


@app.route("/login", methods=["POST"])
def login():
    cfg = _current_cfg()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ttl_seconds = int(request.form.get("ttl_seconds", "3600") or "3600")

    try:
        db = load_user_db(cfg["user_db_path"])
        result, err = authenticate_user(db, username, password, ttl_seconds=max(60, ttl_seconds))
        if err:
            flash(f"Login failed: {err}", "error")
            return redirect(url_for("index"))
        session["user"] = {
            "username": username,
            "auth_token": result["auth_token"],
        }
        flash("Login successful.", "ok")
        return redirect(url_for("search_page"))
    except Exception as exc:
        flash(f"Login error: {exc}", "error")
        return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    flash("Logged out.", "ok")
    return redirect(url_for("index"))


@app.route("/search")
@require_user
def search_page():
    cfg = _current_cfg()
    return render_template(
        "search.html",
        cfg=cfg,
        user=session.get("user", {}),
        csp_running=runtime.running(),
        results=[],
        summary=None,
        form_data={},
    )


@app.route("/search", methods=["POST"])
@require_user
def search_submit():
    cfg = _current_cfg()
    user = session.get("user", {})
    query = request.form.get("query", "").strip()
    mode = request.form.get("expansion_mode", "fallback").strip()
    top_k = max(1, int(request.form.get("top_k", "20") or "20"))
    max_exp = max(1, int(request.form.get("max_expansion_terms", "5") or "5"))
    form_data = {
        "query": query,
        "expansion_mode": mode,
        "top_k": top_k,
        "max_expansion_terms": max_exp,
    }
    if not query:
        flash("Query is required.", "error")
        return render_template(
            "search.html",
            cfg=cfg,
            user=user,
            csp_running=runtime.running(),
            results=[],
            summary=None,
            form_data=form_data,
        )

    try:
        endpoints = csp_endpoints(cfg)
        aui, keys = load_index_artifacts(cfg["aui_path"], cfg["keys_path"])
        core_cfg = load_core_config(cfg["config_path"])

        llm_callable = None
        expansion_message = ""
        if mode == "gemini":
            try:
                llm_callable = make_gemini_llm()
                expansion_message = "Gemini expansion active."
            except Exception as exc:
                expansion_message = f"Gemini unavailable ({exc}); fallback expansion used."
                llm_callable = None

        if mode == "none":
            plans = [prepare_query_plan(query, aui, core_cfg)]
            expanded_tokens = None
            subquery_texts = [query]
            added_tokens = []
        else:
            expanded = prepare_query_plan_with_expansion(
                query,
                aui,
                core_cfg,
                llm_callable=llm_callable if mode == "gemini" else None,
                max_terms=max_exp,
            )
            plans = expanded.plans
            expanded_tokens = expanded.expansion.expanded_tokens
            subquery_texts = expanded.query_texts
            added_tokens = expanded.expansion.added_tokens

        if not plans:
            raise RuntimeError("No query plans generated.")
        if len(endpoints) != plans[0].num_parties:
            raise RuntimeError(f"CSP endpoint count mismatch: expected {plans[0].num_parties}, got {len(endpoints)}.")

        verify_all = True
        union_hits = set()
        hit_sources: Dict[str, set] = {}
        subqueries = []
        for idx, (plan, qtext) in enumerate(zip(plans, subquery_texts)):
            ok_verify, hits = _run_one_plan(plan, endpoints, user["auth_token"], aui, keys)
            verify_all = verify_all and ok_verify
            for hid in hits:
                union_hits.add(hid)
                hit_sources.setdefault(str(hid), set()).add(idx)
            subqueries.append({"query": qtext, "hits": len(hits), "verify": ok_verify})

        import pandas as pd

        raw_df = pd.read_csv(cfg["dataset_path"], sep=";")
        view = raw_df[raw_df["IPEDSID"].astype(str).isin([str(x) for x in union_hits])]
        ranked = rank_results_by_priority(
            query,
            view.to_dict("records"),
            expanded_tokens=expanded_tokens,
            hit_sources=hit_sources,
        )

        results = []
        for idx, item in enumerate(ranked[:top_k], 1):
            row = item["record"]
            results.append(
                {
                    "rank": idx,
                    "id": str(row.get("IPEDSID", "")),
                    "name": str(row.get("NAME", "")),
                    "city": str(row.get("CITY", "")),
                    "state": str(row.get("STATE", "")),
                    "address": str(row.get("ADDRESS", "")),
                    "geo": str(row.get("Geo Point", "")),
                    "score": f"{float(item.get('score', 0.0)):.2f}",
                    "source": _source_label(bool(item.get("base_hit", False)), int(item.get("source_hits", 0))),
                }
            )

        summary = {
            "verify": "pass" if verify_all else "fail",
            "match_count": len(union_hits),
            "added_tokens": added_tokens,
            "subqueries": subqueries,
            "expansion_message": expansion_message,
        }
        return render_template(
            "search.html",
            cfg=cfg,
            user=user,
            csp_running=runtime.running(),
            results=results,
            summary=summary,
            form_data=form_data,
        )
    except Exception as exc:
        flash(f"Search failed: {exc}", "error")
        return render_template(
            "search.html",
            cfg=cfg,
            user=user,
            csp_running=runtime.running(),
            results=[],
            summary=None,
            form_data=form_data,
        )


@app.route("/admin")
def admin_login_page():
    cfg = _current_cfg()
    if _is_admin():
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html", cfg=cfg, csp_running=runtime.running())


@app.route("/admin/login", methods=["POST"])
def admin_login():
    cfg = _current_cfg()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    db = load_user_db(cfg["user_db_path"])
    result, err = authenticate_user(db, username, password, ttl_seconds=3600)
    if err:
        flash(f"Admin login failed: {err}", "error")
        return redirect(url_for("admin_login_page"))
    perms = result["user"]["permissions"]
    if not (perms.get("can_manage_users") or perms.get("can_manage_groups")):
        flash("Not an admin account.", "error")
        return redirect(url_for("admin_login_page"))
    session["admin_user"] = {"username": username}
    flash("Admin login successful.", "ok")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin_user", None)
    flash("Admin logout successful.", "ok")
    return redirect(url_for("admin_login_page"))


@app.route("/admin/dashboard")
@require_admin
def admin_dashboard():
    cfg = _current_cfg()
    db = load_user_db(cfg["user_db_path"])
    return render_template(
        "admin_dashboard.html",
        cfg=cfg,
        csp_running=runtime.running(),
        users=list_users_public(db),
        groups=db.get("groups", {}),
        ports_csv=ports_to_csv(cfg["csp_ports"]),
    )


@app.route("/admin/settings", methods=["POST"])
@require_admin
def admin_save_settings():
    cfg = _current_cfg()
    try:
        cfg["aui_path"] = request.form.get("aui_path", cfg["aui_path"]).strip()
        cfg["keys_path"] = request.form.get("keys_path", cfg["keys_path"]).strip()
        cfg["config_path"] = request.form.get("config_path", cfg["config_path"]).strip()
        cfg["dataset_path"] = request.form.get("dataset_path", cfg["dataset_path"]).strip()
        cfg["user_db_path"] = request.form.get("user_db_path", cfg["user_db_path"]).strip()
        cfg["csp_ports"] = parse_ports_csv(request.form.get("csp_ports", ports_to_csv(cfg["csp_ports"])))
        save_config(cfg)
        flash("Settings saved.", "ok")
    except Exception as exc:
        flash(f"Save settings failed: {exc}", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/csp/start", methods=["POST"])
@require_admin
def admin_start_csp():
    cfg = _current_cfg()
    try:
        runtime.start_csp(cfg)
        flash(f"CSP servers started on ports: {ports_to_csv(cfg['csp_ports'])}", "ok")
    except Exception as exc:
        flash(f"Failed to start CSP servers: {exc}", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/csp/stop", methods=["POST"])
@require_admin
def admin_stop_csp():
    runtime.stop_csp()
    flash("CSP servers stopped.", "ok")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/group/upsert", methods=["POST"])
@require_admin
def admin_group_upsert():
    cfg = _current_cfg()
    db = load_user_db(cfg["user_db_path"])
    try:
        group_name = request.form.get("group_name", "").strip()
        if not group_name:
            raise ValueError("group_name is required")
        policy = {
            "can_search": bool(request.form.get("can_search")),
            "allow_spatial": bool(request.form.get("allow_spatial")),
            "max_keywords": int(request.form.get("max_keywords", "0") or "0"),
            "can_manage_users": bool(request.form.get("can_manage_users")),
            "can_manage_groups": bool(request.form.get("can_manage_groups")),
        }
        create_or_update_group(db, group_name, policy)
        save_user_db(db, cfg["user_db_path"])
        flash(f"Group '{group_name}' saved.", "ok")
    except Exception as exc:
        flash(f"Group save failed: {exc}", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/upsert", methods=["POST"])
@require_admin
def admin_user_upsert():
    cfg = _current_cfg()
    db = load_user_db(cfg["user_db_path"])
    try:
        username = request.form.get("username", "").strip()
        if not username:
            raise ValueError("username is required")
        password = request.form.get("password", "").strip() or None
        groups_raw = request.form.get("groups_csv", "").strip()
        groups = [g.strip() for g in groups_raw.split(",") if g.strip()]
        active = bool(request.form.get("active"))
        for g in groups:
            if g not in db.get("groups", {}):
                raise ValueError(f"unknown group: {g}")
        create_or_update_user(db, username, password=password, groups=groups, active=active)
        save_user_db(db, cfg["user_db_path"])
        flash(f"User '{username}' saved.", "ok")
    except Exception as exc:
        flash(f"User save failed: {exc}", "error")
    return redirect(url_for("admin_dashboard"))


def main():
    cfg = _current_cfg()
    app.run(host=cfg["web_host"], port=int(cfg["web_port"]), debug=False)


if __name__ == "__main__":
    main()
