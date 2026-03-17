from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Ensure project root on sys.path
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from config_loader import load_config
from online_demo.runtime_utils import http_post, login_and_get_token
from secure_search import (
    QueryPlan,
    combine_csp_responses,
    decrypt_matches,
    prepare_query_plan,
    prepare_query_plan_with_expansion,
    rank_results_by_priority,
    run_fx_hmac_verification,
)
from secure_search.indexing import load_index_artifacts

try:
    from ai_clients import make_gemini_llm
except ImportError:  # pragma: no cover
    make_gemini_llm = None


class ClientApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("ST-VLS Search Console")
        self.root.geometry("1160x760")
        self.root.minsize(1040, 700)

        default_aui = os.path.join(PROJ_ROOT, "online_demo", "aui.pkl")
        default_keys = os.path.join(PROJ_ROOT, "online_demo", "K.pkl")
        default_cfg = os.path.join(PROJ_ROOT, "conFig.ini")
        default_dataset = os.path.join(PROJ_ROOT, "us-colleges-and-universities.csv")

        self.aui_path_var = tk.StringVar(value=default_aui)
        self.keys_path_var = tk.StringVar(value=default_keys)
        self.config_path_var = tk.StringVar(value=default_cfg)
        self.dataset_path_var = tk.StringVar(value=default_dataset)
        self.endpoints_var = tk.StringVar(value="http://127.0.0.1:8001, http://127.0.0.1:8002, http://127.0.0.1:8003")
        self.username_var = tk.StringVar(value="alice")
        self.password_var = tk.StringVar(value="alice123")
        self.token_ttl_var = tk.IntVar(value=3600)
        self.query_var = tk.StringVar()
        self.expansion_mode_var = tk.StringVar(value="fallback")
        self.max_expansion_terms_var = tk.IntVar(value=5)
        self.top_k_var = tk.IntVar(value=20)
        self.status_var = tk.StringVar(value="Index not loaded")
        self._table_rows: list[dict] = []
        self._sort_column = "rank"
        self._sort_reverse = False

        self._configure_style()
        self._build_layout()

        self.aui: dict | None = None
        self.keys: tuple | None = None
        self.config: dict | None = None
        self.query_queue: queue.Queue = queue.Queue()
        self.root.after(120, self._process_queue)
        self._llm_callable = None
        self._llm_initialized = False
        self._llm_message = ""

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self.root.configure(bg="#f2f6fb")
        style.configure("Root.TFrame", background="#f2f6fb")
        style.configure("Card.TLabelframe", background="#ffffff", borderwidth=1, relief="solid")
        style.configure("Card.TLabelframe.Label", background="#ffffff", foreground="#16324f", font=("Segoe UI Semibold", 10))
        style.configure("Title.TLabel", background="#f2f6fb", foreground="#0f2740", font=("Segoe UI Semibold", 16))
        style.configure("Sub.TLabel", background="#f2f6fb", foreground="#486581", font=("Segoe UI", 9))
        style.configure("Status.TLabel", background="#f2f6fb", foreground="#133b5c", font=("Segoe UI", 10, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 10))
        style.configure("TButton", font=("Segoe UI", 9))
        style.configure("TLabel", font=("Segoe UI", 9))
        style.configure("TEntry", font=("Consolas", 10))
        style.configure("TCombobox", font=("Segoe UI", 9))
        style.configure("Treeview", font=("Segoe UI", 9), rowheight=24)
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))

    def _add_path_row(self, parent: ttk.Frame, row: int, label: str, var: tk.StringVar) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="ew", padx=(0, 6), pady=6)

        def browse() -> None:
            path = filedialog.askopenfilename(initialdir=PROJ_ROOT)
            if path:
                var.set(path)

        ttk.Button(parent, text="Browse", command=browse).grid(row=row, column=2, padx=(0, 8), pady=6)

    def _build_layout(self) -> None:
        root_frame = ttk.Frame(self.root, style="Root.TFrame", padding=14)
        root_frame.pack(fill=tk.BOTH, expand=True)
        root_frame.columnconfigure(0, weight=1)
        root_frame.rowconfigure(4, weight=1)

        ttk.Label(root_frame, text="ST-VLS Client Dashboard", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(root_frame, text="Secure search + RBAC + expansion ranking", style="Sub.TLabel").grid(
            row=1, column=0, sticky="w", pady=(0, 8)
        )

        top = ttk.Frame(root_frame, style="Root.TFrame")
        top.grid(row=2, column=0, sticky="nsew")
        top.columnconfigure(0, weight=3)
        top.columnconfigure(1, weight=2)

        left = ttk.LabelFrame(top, text="Artifacts & Query", style="Card.TLabelframe", padding=(10, 8))
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 8))
        left.columnconfigure(1, weight=1)

        self._add_path_row(left, 0, "AUI path:", self.aui_path_var)
        self._add_path_row(left, 1, "Keys path:", self.keys_path_var)
        self._add_path_row(left, 2, "Config path:", self.config_path_var)
        self._add_path_row(left, 3, "Dataset path:", self.dataset_path_var)

        ttk.Label(left, text="CSP endpoints:").grid(row=4, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Entry(left, textvariable=self.endpoints_var).grid(row=4, column=1, columnspan=2, sticky="ew", padx=(0, 8), pady=6)

        ttk.Label(left, text="Query:").grid(row=5, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Entry(left, textvariable=self.query_var).grid(row=5, column=1, columnspan=2, sticky="ew", padx=(0, 8), pady=6)

        ttk.Label(
            left,
            text="Format: KW1 KW2 ...; optional R: lat_min,lon_min,lat_max,lon_max",
            foreground="#58748f",
        ).grid(row=6, column=1, columnspan=2, sticky="w", padx=(0, 8), pady=(0, 6))

        right = ttk.LabelFrame(top, text="Auth & Ranking", style="Card.TLabelframe", padding=(10, 8))
        right.grid(row=0, column=1, sticky="nsew", pady=(0, 8))
        right.columnconfigure(1, weight=1)

        ttk.Label(right, text="Username:").grid(row=0, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Entry(right, textvariable=self.username_var).grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=6)

        ttk.Label(right, text="Password:").grid(row=1, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Entry(right, textvariable=self.password_var, show="*").grid(row=1, column=1, sticky="ew", padx=(0, 8), pady=6)

        ttk.Label(right, text="Token TTL(s):").grid(row=2, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Spinbox(right, from_=300, to=86400, increment=300, textvariable=self.token_ttl_var, width=10).grid(
            row=2, column=1, sticky="w", padx=(0, 8), pady=6
        )

        ttk.Label(right, text="Expansion mode:").grid(row=3, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Combobox(
            right,
            textvariable=self.expansion_mode_var,
            values=["none", "fallback", "gemini"],
            state="readonly",
        ).grid(row=3, column=1, sticky="ew", padx=(0, 8), pady=6)

        ttk.Label(right, text="Max expansion terms:").grid(row=4, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Spinbox(right, from_=1, to=10, textvariable=self.max_expansion_terms_var, width=10).grid(
            row=4, column=1, sticky="w", padx=(0, 8), pady=6
        )

        ttk.Label(right, text="Top-K display:").grid(row=5, column=0, sticky="e", padx=(8, 6), pady=6)
        ttk.Spinbox(right, from_=5, to=100, increment=5, textvariable=self.top_k_var, width=10).grid(
            row=5, column=1, sticky="w", padx=(0, 8), pady=6
        )

        ttk.Label(right, text="Default user: alice / alice123", foreground="#58748f").grid(
            row=6, column=0, columnspan=2, sticky="w", padx=(8, 8), pady=(2, 4)
        )

        actions = ttk.Frame(root_frame, style="Root.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(actions, text="Load Index", command=self.load_index).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(actions, text="Examples", command=self.fill_example).pack(side=tk.LEFT, padx=6)
        ttk.Button(actions, text="Run Query", style="Accent.TButton", command=self.run_query).pack(side=tk.LEFT, padx=6)
        ttk.Label(actions, textvariable=self.status_var, style="Status.TLabel").pack(side=tk.RIGHT, padx=4)

        output_card = ttk.LabelFrame(root_frame, text="Results", style="Card.TLabelframe", padding=(8, 8))
        output_card.grid(row=4, column=0, sticky="nsew")
        output_card.columnconfigure(0, weight=1)
        output_card.rowconfigure(1, weight=1)

        self.summary_box = tk.Text(
            output_card,
            height=7,
            bg="#fbfdff",
            fg="#12263a",
            insertbackground="#12263a",
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=8,
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self.summary_box.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        table_frame = ttk.Frame(output_card)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = ("rank", "id", "name", "city", "state", "score", "source", "address", "geo")
        self.result_table = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.result_table.grid(row=0, column=0, sticky="nsew")

        self._column_specs = {
            "rank": ("#", 60, "center"),
            "id": ("IPEDSID", 90, "center"),
            "name": ("Name", 260, "w"),
            "city": ("City", 120, "w"),
            "state": ("State", 70, "center"),
            "score": ("Score", 90, "e"),
            "source": ("Source", 120, "center"),
            "address": ("Address", 280, "w"),
            "geo": ("Geo Point", 180, "w"),
        }
        for col, (label, width, anchor) in self._column_specs.items():
            self.result_table.heading(col, text=label, command=lambda c=col: self._on_sort_column(c))
            self.result_table.column(col, width=width, anchor=anchor, stretch=(col in ("name", "address", "geo")))

        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.result_table.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.result_table.xview)
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.result_table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self._refresh_table_headings()

    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def load_index(self) -> None:
        try:
            self.set_status("Loading index...")
            self.aui, self.keys = load_index_artifacts(self.aui_path_var.get(), self.keys_path_var.get())
            self.config = load_config(self.config_path_var.get())
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to load index: {exc}")
            self.set_status("Index load failed")
            return
        self.set_status("Index loaded successfully")

    def fill_example(self) -> None:
        self.query_var.set("ORLANDO UNIVERSITY; R: 28.2,-81.6,28.8,-81.1")

    def run_query(self) -> None:
        if self.aui is None or self.keys is None or self.config is None:
            self.load_index()
            if self.aui is None:
                return
        query = self.query_var.get().strip()
        if not query:
            messagebox.showwarning("Warning", "Please enter a query string.")
            return
        endpoints = [ep.strip() for ep in self.endpoints_var.get().split(",") if ep.strip()]
        if not endpoints:
            messagebox.showwarning("Warning", "Please provide at least one CSP endpoint.")
            return
        self.set_status("Running query...")
        threading.Thread(target=self._query_worker, args=(query, endpoints), daemon=True).start()

    def _run_one_plan(self, plan: QueryPlan, endpoints: list[str], auth_token: str):
        if len(endpoints) != plan.num_parties:
            raise ValueError(f"Expected {plan.num_parties} CSP endpoints, got {len(endpoints)}")
        responses = []
        for party_id, base in enumerate(endpoints):
            body = {
                "party_id": party_id,
                "tokens": plan.payloads[party_id],
                "security_param": plan.security_param,
                "auth_token": auth_token,
            }
            responses.append(http_post(base + "/eval", body))
        combined_vecs, combined_proofs = combine_csp_responses(plan, responses, self.aui)
        _, hits = decrypt_matches(plan, combined_vecs, self.aui, self.keys)
        ok_verify = run_fx_hmac_verification(plan, combined_vecs, combined_proofs, self.aui, self.keys)
        return ok_verify, hits

    def _refresh_table_headings(self) -> None:
        for col, (label, _width, _anchor) in self._column_specs.items():
            suffix = ""
            if col == self._sort_column:
                suffix = " ▼" if self._sort_reverse else " ▲"
            self.result_table.heading(col, text=label + suffix, command=lambda c=col: self._on_sort_column(c))

    def _sort_key(self, row: dict, column: str):
        if column in ("rank",):
            return int(row.get(column, 0))
        if column in ("score",):
            return float(row.get(column, 0.0))
        if column in ("id",):
            return str(row.get(column, ""))
        return str(row.get(column, "")).lower()

    def _render_table(self) -> None:
        self.result_table.delete(*self.result_table.get_children())
        for row in self._table_rows:
            self.result_table.insert(
                "",
                tk.END,
                values=(
                    row.get("rank", ""),
                    row.get("id", ""),
                    row.get("name", ""),
                    row.get("city", ""),
                    row.get("state", ""),
                    f"{float(row.get('score', 0.0)):.2f}",
                    row.get("source", ""),
                    row.get("address", ""),
                    row.get("geo", ""),
                ),
            )

    def _on_sort_column(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = column
            self._sort_reverse = False
        self._table_rows.sort(key=lambda r: self._sort_key(r, self._sort_column), reverse=self._sort_reverse)
        self._refresh_table_headings()
        self._render_table()

    def _query_worker(self, query: str, endpoints: list[str]) -> None:
        try:
            auth_token = login_and_get_token(
                endpoints[0],
                self.username_var.get().strip(),
                self.password_var.get(),
                ttl_seconds=max(60, int(self.token_ttl_var.get())),
            )

            mode = self.expansion_mode_var.get().strip() or "fallback"
            plans: list[QueryPlan]
            subquery_texts: list[str]
            expansion_data = None
            expansion_message = ""
            if mode == "none":
                plans = [prepare_query_plan(query, self.aui, self.config)]
                subquery_texts = [query]
            else:
                llm_callable = None
                if mode == "gemini":
                    llm_callable = self._get_llm_callable()
                    expansion_message = self._llm_message
                expanded_plan = prepare_query_plan_with_expansion(
                    query,
                    self.aui,
                    self.config,
                    llm_callable=llm_callable,
                    max_terms=max(1, int(self.max_expansion_terms_var.get())),
                )
                plans = expanded_plan.plans
                subquery_texts = expanded_plan.query_texts
                expansion_data = {
                    "added_tokens": expanded_plan.expansion.added_tokens,
                    "expanded_tokens": expanded_plan.expansion.expanded_tokens,
                    "token_expansions": expanded_plan.expansion.token_expansions,
                }

            hits_union: set = set()
            subqueries: list[dict] = []
            hit_sources: dict[str, set[int]] = {}
            verify_all = True
            for idx, (sub_query, plan) in enumerate(zip(subquery_texts, plans)):
                ok_verify, hits = self._run_one_plan(plan, endpoints, auth_token)
                verify_all = verify_all and ok_verify
                hits_union.update(hits)
                for hid in hits:
                    hit_sources.setdefault(str(hid), set()).add(idx)
                subqueries.append({"query": sub_query, "hits": hits, "verify": ok_verify})

            dataset_path = self.dataset_path_var.get().strip()
            if not dataset_path:
                raise ValueError("Dataset path is required for result display.")
            table_rows: list[dict] = []
            render_error = ""
            hits_list = sorted(hits_union)
            try:
                import pandas as pd

                raw_df = pd.read_csv(dataset_path, sep=";")
                view = raw_df[raw_df["IPEDSID"].astype(str).isin([str(x) for x in hits_list])]
                ranked = rank_results_by_priority(
                    query,
                    view.to_dict("records"),
                    expanded_tokens=(expansion_data["expanded_tokens"] if expansion_data else None),
                    hit_sources=hit_sources,
                )

                def source_label(base_hit: bool, source_hits: int) -> str:
                    if source_hits <= 0:
                        return "none"
                    if base_hit and source_hits == 1:
                        return "base"
                    if base_hit:
                        return f"base+{source_hits - 1}exp"
                    return f"{source_hits}exp"

                for idx, item in enumerate(ranked[: max(1, int(self.top_k_var.get()))], 1):
                    row = item["record"]
                    table_rows.append(
                        {
                            "rank": idx,
                            "id": str(row.get("IPEDSID", "")),
                            "name": str(row.get("NAME", "")),
                            "city": str(row.get("CITY", "")),
                            "state": str(row.get("STATE", "")),
                            "score": float(item.get("score", 0.0)),
                            "source": source_label(item["base_hit"], item["source_hits"]),
                            "address": str(row.get("ADDRESS", "")),
                            "geo": str(row.get("Geo Point", "")),
                        }
                    )
            except Exception as exc:
                render_error = f"Failed to render ranked dataset rows: {exc}"

            self.query_queue.put(
                (
                    "result",
                    {
                        "verify": verify_all,
                        "hits": hits_list,
                        "table_rows": table_rows,
                        "render_error": render_error,
                        "subqueries": subqueries,
                        "expansion": expansion_data,
                        "expansion_message": expansion_message,
                        "auth_user": self.username_var.get().strip(),
                        "mode": mode,
                    },
                )
            )
        except Exception as exc:
            self.query_queue.put(("error", str(exc)))

    def _process_queue(self) -> None:
        try:
            while True:
                kind, payload = self.query_queue.get_nowait()
                if kind == "error":
                    messagebox.showerror("Error", payload)
                    self.set_status("Query failed")
                elif kind == "result":
                    self.set_status("Query finished")
                    self.summary_box.configure(state=tk.NORMAL)
                    self.summary_box.delete("1.0", tk.END)
                    verify_text = "pass" if payload["verify"] else "fail"
                    self.summary_box.insert(tk.END, f"Verify: {verify_text}\n")
                    self.summary_box.insert(tk.END, f"User: {payload['auth_user']}  |  Expansion mode: {payload['mode']}\n")
                    self.summary_box.insert(tk.END, f"Total matches: {len(payload['hits'])}\n")
                    if payload.get("expansion"):
                        added = payload["expansion"].get("added_tokens", [])
                        self.summary_box.insert(tk.END, f"Added keywords: {', '.join(added) if added else 'None'}\n")
                    if payload.get("expansion_message"):
                        self.summary_box.insert(tk.END, payload["expansion_message"] + "\n")
                    if payload.get("subqueries"):
                        self.summary_box.insert(tk.END, "Subqueries:\n")
                        for idx, item in enumerate(payload["subqueries"], 1):
                            q_verify = "pass" if item["verify"] else "fail"
                            self.summary_box.insert(
                                tk.END,
                                f"  {idx}. {item['query']} -> {len(item['hits'])} hits (verify {q_verify})\n",
                            )
                    if payload.get("render_error"):
                        self.summary_box.insert(tk.END, payload["render_error"] + "\n")
                    self.summary_box.configure(state=tk.DISABLED)
                    self.summary_box.see("1.0")

                    self._table_rows = list(payload.get("table_rows", []))
                    self._sort_column = "rank"
                    self._sort_reverse = False
                    self._refresh_table_headings()
                    self._render_table()
        except queue.Empty:
            pass
        finally:
            self.root.after(120, self._process_queue)

    def _get_llm_callable(self):
        if self._llm_initialized:
            return self._llm_callable
        self._llm_initialized = True
        if make_gemini_llm is None:
            self._llm_message = "Gemini package not installed; fallback expansion is used."
            self._llm_callable = None
            return None
        try:
            self._llm_callable = make_gemini_llm()
            self._llm_message = "Gemini expansion active."
        except Exception as exc:
            self._llm_callable = None
            self._llm_message = f"Gemini unavailable ({exc}); fallback expansion is used."
        return self._llm_callable

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    app = ClientApp()
    app.run()


if __name__ == "__main__":
    main()
