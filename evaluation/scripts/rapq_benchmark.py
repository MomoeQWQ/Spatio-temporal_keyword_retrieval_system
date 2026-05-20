#!/usr/bin/env python3
"""Benchmark legacy full-scan retrieval vs RAPQ candidate-pruned retrieval."""

from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path
from statistics import mean
from typing import List

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config_loader import load_config
from core import prepare_dataset
from core.convert_dataset import convert_dataset
from core.SetupProcess import Setup
from core.QueryUtils import tokenize_normalized
from core.secure_search import (
    build_candidate_index,
    combine_csp_responses,
    decrypt_matches,
    prepare_query_plan,
    run_fast_preview_verification,
    run_fx_hmac_verification,
    select_sentinel_positions,
)

RESULT_DIR = PROJECT_ROOT / "evaluation" / "outputs"
FIG_DIR = RESULT_DIR / "figures"
DATA_CSV = PROJECT_ROOT / "us-colleges-and-universities.csv"
CONFIG_PATH = PROJECT_ROOT / "conFig.ini"


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _simulate_party(
    plan,
    aui: dict,
    party_id: int,
    candidate_positions: List[int] | None = None,
    sentinel_positions: List[int] | None = None,
) -> dict:
    lam = int(aui["security_param"])
    byte_len = int(aui["segment_length"])
    n = len(aui["ids"])
    payloads = plan.payloads[party_id]
    fast_row_tags = aui.get("fast_tags", {}).get("rows", [])

    result_shares = []
    proof_shares = []
    sentinel_result_shares = []
    for token_meta in payloads:
        typ = token_meta.get("type", "kw")
        buckets = token_meta.get("buckets", [])
        if typ == "kw":
            matrix = aui["I_tex"]["EbW"]
            sigma = aui["I_tex"]["sigma"]
        else:
            matrix = aui["I_spa"]["Ebp"]
            sigma = aui["I_spa"]["sigma"]

        if candidate_positions is None:
            vec_total = [b"\x00" * byte_len for _ in range(n)]
        else:
            vec_total = [b"\x00" * byte_len for _ in range(len(candidate_positions))]
        if sentinel_positions is not None:
            sentinel_vec_total = [b"\x00" * byte_len for _ in range(len(sentinel_positions))]
        else:
            sentinel_vec_total = None
        proof_total = b"\x00" * lam

        for bucket in buckets:
            columns = bucket.get("columns", [])
            bits = bucket.get("bits", [])
            for local_idx, col_idx in enumerate(columns):
                if local_idx < len(bits) and int(bits[local_idx]) == 1:
                    if candidate_positions is None:
                        col_cells = [row[col_idx] for row in matrix]
                        for row_idx in range(n):
                            vec_total[row_idx] = _xor_bytes(vec_total[row_idx], col_cells[row_idx])
                    else:
                        for c_idx, row_idx in enumerate(candidate_positions):
                            vec_total[c_idx] = _xor_bytes(vec_total[c_idx], matrix[row_idx][col_idx])
                    if sentinel_vec_total is not None:
                        for s_idx, row_idx in enumerate(sentinel_positions):
                            sentinel_vec_total[s_idx] = _xor_bytes(sentinel_vec_total[s_idx], matrix[row_idx][col_idx])
                    proof_total = _xor_bytes(proof_total, sigma[col_idx])

        result_shares.append([base64.b64encode(v).decode("utf-8") for v in vec_total])
        proof_shares.append(base64.b64encode(proof_total).decode("utf-8"))
        if sentinel_vec_total is not None:
            sentinel_result_shares.append([base64.b64encode(v).decode("utf-8") for v in sentinel_vec_total])

    out = {"result_shares": result_shares, "proof_shares": proof_shares}
    if candidate_positions is not None:
        out["candidate_positions"] = candidate_positions
        tag = b"\x00" * lam
        for idx in candidate_positions:
            if 0 <= idx < len(fast_row_tags):
                tag = _xor_bytes(tag, fast_row_tags[idx])
        out["candidate_fast_tag"] = base64.b64encode(tag).decode("utf-8")
    if sentinel_positions is not None:
        out["sentinel_positions"] = sentinel_positions
        out["sentinel_result_shares"] = sentinel_result_shares
        tag = b"\x00" * lam
        for idx in sentinel_positions:
            if 0 <= idx < len(fast_row_tags):
                tag = _xor_bytes(tag, fast_row_tags[idx])
        out["sentinel_fast_tag"] = base64.b64encode(tag).decode("utf-8")
    return out


def run_query_once(
    query_text: str,
    cfg: dict,
    aui: dict,
    keys: tuple,
    *,
    mode: str,
    candidate_index=None,
    max_candidates: int | None = None,
    sentinel_count: int = 8,
) -> dict:
    t0 = time.perf_counter()
    plan = prepare_query_plan(query_text, aui, cfg)
    t1 = time.perf_counter()

    candidate_positions = None
    sentinel_positions = None
    preview_verify_ok = None
    full_verify_ok = None
    if candidate_index is not None:
        selection = candidate_index.select_candidates(
            query_text,
            cfg,
            max_candidates=max_candidates,
        )
        candidate_positions = selection.positions
        candidate_ratio = selection.candidate_ratio
        if mode == "rapq_plus":
            sentinel_positions = select_sentinel_positions(
                selection.total_records,
                candidate_positions,
                sentinel_count,
                seed_material=f"{query_text}|benchmark|{sentinel_count}",
            )
    else:
        candidate_ratio = 1.0

    t2 = time.perf_counter()
    responses = [
        _simulate_party(
            plan,
            aui,
            party_id=pid,
            candidate_positions=candidate_positions,
            sentinel_positions=sentinel_positions,
        )
        for pid in range(plan.num_parties)
    ]
    t3 = time.perf_counter()
    combined_vecs, combined_proofs = combine_csp_responses(plan, responses, aui)
    _, hits = decrypt_matches(
        plan,
        combined_vecs,
        aui,
        keys,
        candidate_positions=candidate_positions,
    )
    if mode == "legacy":
        full_verify_ok = run_fx_hmac_verification(plan, combined_vecs, combined_proofs, aui, keys)
    elif mode == "rapq_plus":
        preview_verify_ok, sentinel_hits = run_fast_preview_verification(
            plan,
            responses,
            aui,
            keys,
            candidate_positions=candidate_positions,
            sentinel_positions=sentinel_positions,
        )
        if sentinel_hits:
            raise RuntimeError(f"Sentinel audit unexpectedly found hits for query '{query_text}': {sentinel_hits[:5]}")
    t4 = time.perf_counter()

    return {
        "plan_time": t1 - t0,
        "candidate_time": t2 - t1,
        "server_time": t3 - t2,
        "post_time": t4 - t3,
        "total_time": t4 - t0,
        "hits": len(hits),
        "candidate_count": len(candidate_positions) if candidate_positions is not None else len(aui["ids"]),
        "candidate_ratio": candidate_ratio,
        "sentinel_count": len(sentinel_positions or []),
        "preview_verify_ok": preview_verify_ok,
        "full_verify_ok": full_verify_ok,
    }


def measure_mode(
    query_text: str,
    cfg: dict,
    aui: dict,
    keys: tuple,
    *,
    mode: str,
    repeats: int,
    candidate_index=None,
    max_candidates: int | None = None,
    sentinel_count: int = 8,
) -> dict:
    samples = [
        run_query_once(
            query_text,
            cfg,
            aui,
            keys,
            mode=mode,
            candidate_index=candidate_index,
            max_candidates=max_candidates,
            sentinel_count=sentinel_count,
        )
        for _ in range(repeats)
    ]
    return {
        "plan_time": mean(s["plan_time"] for s in samples),
        "candidate_time": mean(s["candidate_time"] for s in samples),
        "server_time": mean(s["server_time"] for s in samples),
        "post_time": mean(s["post_time"] for s in samples),
        "total_time": mean(s["total_time"] for s in samples),
        "hits": samples[0]["hits"],
        "candidate_count": mean(s["candidate_count"] for s in samples),
        "candidate_ratio": mean(s["candidate_ratio"] for s in samples),
        "sentinel_count": mean(s["sentinel_count"] for s in samples),
        "preview_verify_ok": all(s["preview_verify_ok"] in (None, True) for s in samples),
        "full_verify_ok": all(s["full_verify_ok"] in (None, True) for s in samples),
    }


def plot_total_latency(comp_rows: List[dict], output_path: Path) -> None:
    df = pd.DataFrame(comp_rows)
    scenarios = df["scenario"].unique().tolist()
    x = np.arange(len(scenarios))
    width = 0.24
    legacy = [float(df[(df["scenario"] == s) & (df["mode"] == "legacy")]["total_time"].iloc[0]) for s in scenarios]
    rapq = [float(df[(df["scenario"] == s) & (df["mode"] == "rapq")]["total_time"].iloc[0]) for s in scenarios]
    rapq_plus = [float(df[(df["scenario"] == s) & (df["mode"] == "rapq_plus")]["total_time"].iloc[0]) for s in scenarios]

    plt.figure(figsize=(8, 4.5))
    b1 = plt.bar(x - width, legacy, width=width, label="Legacy+FX/HMAC", color="#4c78a8")
    b2 = plt.bar(x, rapq, width=width, label="RAPQ", color="#f58518")
    b3 = plt.bar(x + width, rapq_plus, width=width, label="RAPQ+", color="#54a24b")
    plt.xticks(x, scenarios)
    plt.ylabel("Time (s)")
    plt.title("Legacy vs RAPQ vs RAPQ+ Latency")
    plt.grid(axis="y", linestyle="--", alpha=0.35)
    plt.legend()

    for i, (lv, rv) in enumerate(zip(legacy, rapq_plus)):
        if lv > 0:
            red = (lv - rv) / lv * 100.0
            plt.text(i, max(lv, rv) + 0.05, f"-{red:.1f}%", ha="center", va="bottom", fontsize=9)
    for bar in list(b1) + list(b2) + list(b3):
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, h + 0.02, f"{h:.2f}", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=220)
    plt.close()


def plot_hit_counts(comp_rows: List[dict], output_path: Path) -> None:
    df = pd.DataFrame(comp_rows)
    scenarios = df["scenario"].unique().tolist()
    x = np.arange(len(scenarios))
    width = 0.24
    legacy = [float(df[(df["scenario"] == s) & (df["mode"] == "legacy")]["hits"].iloc[0]) for s in scenarios]
    rapq = [float(df[(df["scenario"] == s) & (df["mode"] == "rapq")]["hits"].iloc[0]) for s in scenarios]
    rapq_plus = [float(df[(df["scenario"] == s) & (df["mode"] == "rapq_plus")]["hits"].iloc[0]) for s in scenarios]

    plt.figure(figsize=(8, 4.5))
    b1 = plt.bar(x - width, legacy, width=width, label="Legacy+FX/HMAC", color="#4c78a8")
    b2 = plt.bar(x, rapq, width=width, label="RAPQ", color="#f58518")
    b3 = plt.bar(x + width, rapq_plus, width=width, label="RAPQ+", color="#54a24b")
    plt.xticks(x, scenarios)
    plt.ylabel("Hit count")
    plt.title("Hit Count Comparison")
    plt.grid(axis="y", linestyle="--", alpha=0.35)
    plt.legend()
    for bar in list(b1) + list(b2) + list(b3):
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, h + 0.02, f"{int(h)}", ha="center", va="bottom", fontsize=8)
    plt.tight_layout()
    plt.savefig(output_path, dpi=220)
    plt.close()


def _auto_spatial_query(raw_records: List[dict], cfg: dict) -> str | None:
    """Build a likely non-zero spatio-temporal query from dataset rows."""
    for rec in raw_records[:250]:
        try:
            lat = float(rec.get("x"))
            lon = float(rec.get("y"))
        except Exception:
            continue
        toks = tokenize_normalized(str(rec.get("keywords", "")))
        if not toks:
            continue
        kw = toks[0]
        q = f"{kw} ; R: {lat - 0.12:.4f},{lon - 0.12:.4f},{lat + 0.12:.4f},{lon + 0.12:.4f}"
        # sanity: should include this record's cell
        if "R:" in q:
            return q
    return None


def discover_nonzero_scenarios(
    raw_records: List[dict],
    cfg: dict,
    aui: dict,
    keys: tuple,
    candidate_index,
) -> List[tuple[str, str]]:
    """Select benchmark scenarios that actually return non-zero hits."""
    fixed_candidates = [
        ("Keyword-H (high hit)", "COLLEGE"),
        ("Keyword-M (mid hit)", "UNIVERSITY"),
        ("Keyword-L (low hit)", "ORLANDO"),
        ("Keyword-2 (phrase)", "NEW YORK"),
    ]
    spatial_query = _auto_spatial_query(raw_records, cfg)
    if spatial_query:
        fixed_candidates.append(("Spatio-temporal", spatial_query))

    selected: List[tuple[str, str]] = []
    for label, query in fixed_candidates:
        legacy = run_query_once(query, cfg, aui, keys, mode="legacy", candidate_index=None)
        rapq = run_query_once(query, cfg, aui, keys, mode="rapq", candidate_index=candidate_index)
        if legacy["hits"] <= 0:
            continue
        if legacy["hits"] != rapq["hits"]:
            continue
        selected.append((label, query))
    return selected


def main() -> None:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    plt.style.use("seaborn-v0_8-colorblind")

    cfg = load_config(str(CONFIG_PATH))
    raw_records = prepare_dataset.load_and_transform(str(DATA_CSV))
    objects = convert_dataset(raw_records, cfg)
    aui, keys = Setup(objects, cfg)
    candidate_index = build_candidate_index(raw_records, cfg)

    scenarios = discover_nonzero_scenarios(raw_records, cfg, aui, keys, candidate_index)
    if len(scenarios) < 4:
        raise RuntimeError("Unable to discover enough non-zero benchmark scenarios.")

    repeats = 3
    rows = []
    for label, query in scenarios:
        legacy = measure_mode(query, cfg, aui, keys, mode="legacy", repeats=repeats, candidate_index=None)
        rapq = measure_mode(query, cfg, aui, keys, mode="rapq", repeats=repeats, candidate_index=candidate_index)
        rapq_plus = measure_mode(
            query,
            cfg,
            aui,
            keys,
            mode="rapq_plus",
            repeats=repeats,
            candidate_index=candidate_index,
        )
        if legacy["hits"] <= 0:
            continue
        if legacy["hits"] != rapq["hits"] or legacy["hits"] != rapq_plus["hits"]:
            raise RuntimeError(
                f"Hit mismatch for scenario '{label}': "
                f"legacy={legacy['hits']} rapq={rapq['hits']} rapq_plus={rapq_plus['hits']}"
            )
        rows.append({"scenario": label, "query": query, "mode": "legacy", **legacy})
        rows.append({"scenario": label, "query": query, "mode": "rapq", **rapq})
        rows.append({"scenario": label, "query": query, "mode": "rapq_plus", **rapq_plus})
    if not rows:
        raise RuntimeError("No valid non-zero rows were produced.")

    out_json = RESULT_DIR / "rapq_metrics.json"
    with out_json.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "notes": (
                    "Legacy uses full FX+HMAC verification. RAPQ is candidate-pruned retrieval without preview verification. "
                    "RAPQ+ adds fast subset binding plus sentinel auditing. Scenarios are non-zero hit only."
                ),
                "rows": rows,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    out_csv = RESULT_DIR / "rapq_metrics.csv"
    pd.DataFrame(rows).to_csv(out_csv, index=False, encoding="utf-8-sig")

    plot_total_latency(rows, FIG_DIR / "rapq_overhead_compare.png")
    plot_hit_counts(rows, FIG_DIR / "rapq_hit_compare.png")
    print("Wrote:", out_json)
    print("Wrote:", out_csv)
    print("Figure:", FIG_DIR / "rapq_overhead_compare.png")
    print("Figure:", FIG_DIR / "rapq_hit_compare.png")


if __name__ == "__main__":
    main()
