#!/usr/bin/env python3
"""Performance experiments for the privacy-preserving spatio-textual search prototype."""

from __future__ import annotations

import base64
import copy
import json
import sys
import time
from pathlib import Path
from statistics import mean
from typing import List, Tuple

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
from core.secure_search import (
    prepare_query_plan,
    combine_csp_responses,
    decrypt_matches,
    run_fx_hmac_verification,
)
from core.QueryUtils import tokenize_normalized


DATA_CSV = PROJECT_ROOT / "us-colleges-and-universities.csv"
CONFIG_PATH = PROJECT_ROOT / "conFig.ini"
RESULT_DIR = PROJECT_ROOT / "evaluation" / "outputs"
FIG_DIR = RESULT_DIR / "figures"


def load_dataset(csv_path: Path) -> List[dict]:
    """Load raw dataset rows as dictionaries."""
    return prepare_dataset.load_and_transform(str(csv_path))


def build_index(records: List[dict], cfg: dict):
    """Construct the authenticated index and key tuple for a given record slice."""
    objs = convert_dataset(records, cfg)
    return Setup(objs, cfg)


def simulate_party(plan, aui: dict, party_id: int) -> dict:
    """Emulate one CSP server response using the offline plan description."""
    lam = int(aui["security_param"])
    byte_len = int(aui["segment_length"])
    n = len(aui["ids"])
    payloads = plan.payloads[party_id]
    result_shares = []
    proof_shares = []
    for token_meta in payloads:
        typ = token_meta.get("type", "kw")
        buckets = token_meta.get("buckets", [])
        vec_total = [b"\x00" * byte_len for _ in range(n)]
        proof_total = b"\x00" * lam
        if typ == "kw":
            matrix = aui["I_tex"]["EbW"]
            sigma = aui["I_tex"]["sigma"]
        else:
            matrix = aui["I_spa"]["Ebp"]
            sigma = aui["I_spa"]["sigma"]
        for bucket in buckets:
            columns = bucket.get("columns", [])
            bits = bucket.get("bits", [])
            for local_idx, col_idx in enumerate(columns):
                if local_idx < len(bits) and int(bits[local_idx]) == 1:
                    col_cells = [row[col_idx] for row in matrix]
                    for row_idx in range(n):
                        vec_total[row_idx] = bytes(a ^ b for a, b in zip(vec_total[row_idx], col_cells[row_idx]))
                    proof_total = bytes(a ^ b for a, b in zip(proof_total, sigma[col_idx]))
        result_shares.append([base64.b64encode(v).decode("utf-8") for v in vec_total])
        proof_shares.append(base64.b64encode(proof_total).decode("utf-8"))
    return {"result_shares": result_shares, "proof_shares": proof_shares}


def run_query_once(query_text: str, cfg: dict, aui: dict, keys: tuple) -> dict:
    t0 = time.perf_counter()
    plan = prepare_query_plan(query_text, aui, cfg)
    t1 = time.perf_counter()
    responses = [simulate_party(plan, aui, pid) for pid in range(plan.num_parties)]
    t2 = time.perf_counter()
    combined_vecs, combined_proofs = combine_csp_responses(plan, responses, aui)
    t3 = time.perf_counter()
    _, hits = decrypt_matches(plan, combined_vecs, aui, keys)
    verify_ok = run_fx_hmac_verification(plan, combined_vecs, combined_proofs, aui, keys)
    t4 = time.perf_counter()
    return {
        "plan_time": t1 - t0,
        "server_time": t2 - t1,
        "combine_time": t3 - t2,
        "post_time": t4 - t3,
        "total_time": t4 - t0,
        "token_count": len(plan.tokens),
        "tokens": plan.tokens,
        "hits": len(hits),
        "verify_ok": bool(verify_ok),
    }


def measure_query(query_text: str, cfg: dict, aui: dict, keys: tuple, repeats: int = 3) -> dict:
    samples = [run_query_once(query_text, cfg, aui, keys) for _ in range(repeats)]
    if not all(s["verify_ok"] for s in samples):
        raise RuntimeError("Verification failed during query measurement")
    lat_keys = ["plan_time", "server_time", "combine_time", "post_time", "total_time"]
    metrics = {k: mean(sample[k] for sample in samples) for k in lat_keys}
    metrics["client_time"] = metrics["combine_time"] + metrics["post_time"]
    metrics["token_count"] = samples[0]["token_count"]
    metrics["tokens"] = samples[0]["tokens"]
    metrics["hits"] = samples[0]["hits"]
    metrics["query_text"] = query_text
    return metrics


def measure_index_scaling(cfg: dict, dataset: List[dict], sizes: List[int], repeats: int = 3) -> List[dict]:
    results = []
    for n in sizes:
        subset = dataset[:n]
        convert_times = []
        setup_times = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            objs = convert_dataset(subset, cfg)
            t1 = time.perf_counter()
            Setup(objs, cfg)
            t2 = time.perf_counter()
            convert_times.append(t1 - t0)
            setup_times.append(t2 - t1)
        results.append({
            "records": n,
            "convert_time": mean(convert_times),
            "setup_time": mean(setup_times),
            "total_time": mean(convert_times) + mean(setup_times),
        })
    return results


def split_query(query_text: str) -> Tuple[str, str | None]:
    if "R:" in query_text:
        kw, rest = query_text.split("R:", 1)
        return kw.strip(), rest.strip()
    return query_text.strip(), None


def apply_padding(query_text: str, suppression_cfg: dict | None) -> str:
    if not suppression_cfg or not suppression_cfg.get("enable_padding", True):
        return query_text
    max_r = suppression_cfg.get("max_r_blocks", 4)
    kw_part, spatial_part = split_query(query_text)
    tokens = tokenize_normalized(kw_part)
    if not tokens:
        return query_text.strip()
    trimmed = tokens[:max_r]
    kw_rebuilt = " ".join(trimmed)
    if spatial_part:
        return f"{kw_rebuilt} R: {spatial_part}"
    return kw_rebuilt


def measure_party_scaling(cfg: dict, dataset: List[dict], subset_size: int, base_query: str,
                          parties: List[int], repeats: int = 3) -> List[dict]:
    subset = dataset[:subset_size]
    results = []
    for U in parties:
        cfg_u = copy.deepcopy(cfg)
        cfg_u["U"] = U
        aui_u, keys_u = build_index(subset, cfg_u)
        metrics = measure_query(base_query, cfg_u, aui_u, keys_u, repeats=repeats)
        metrics["U"] = U
        results.append(metrics)
    return results


def plot_index_scaling(data: List[dict], output_path: Path) -> None:
    df = pd.DataFrame(data)
    plt.figure(figsize=(6, 4))
    plt.plot(df["records"], df["total_time"], marker="o", label="Total time")
    plt.plot(df["records"], df["convert_time"], marker="^", label="Preprocessing")
    plt.plot(df["records"], df["setup_time"], marker="s", label="Index setup")
    plt.xlabel("Number of records")
    plt.ylabel("Time (s)")
    plt.title("Index build time vs. dataset size")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def plot_query_latency(baseline: List[dict], suppressed: List[dict], output_path: Path) -> None:
    scenarios = [item["scenario"] for item in baseline]
    x = np.arange(len(scenarios))
    width = 0.35
    plt.figure(figsize=(7, 4))
    for offset, mode_data, color, label in [
        (-width / 2, baseline, "#1f77b4", "No padding"),
        ( width / 2, suppressed, "#ff7f0e", "Padding enabled"),
    ]:
        plan = np.array([d["plan_time"] for d in mode_data])
        server = np.array([d["server_time"] for d in mode_data])
        client = np.array([d["client_time"] for d in mode_data])
        positions = x + offset
        plt.bar(positions, plan, width=width, color=color, alpha=0.6)
        plt.bar(positions, server, width=width, bottom=plan, color=color, alpha=0.45)
        plt.bar(positions, client, width=width, bottom=plan + server, color=color, alpha=0.3, label=label)
    plt.xticks(x, scenarios)
    plt.ylabel("Time (s)")
    plt.title("Query latency breakdown")
    plt.legend()
    plt.grid(True, axis="y", linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def plot_party_scaling(data: List[dict], output_path: Path) -> None:
    df = pd.DataFrame(data).sort_values("U")
    plt.figure(figsize=(6, 4))
    plt.plot(df["U"], df["total_time"], marker="o", label="Total time")
    plt.plot(df["U"], df["server_time"], marker="^", label="CSP aggregation")
    plt.plot(df["U"], df["client_time"], marker="s", label="Client combine+verify")
    plt.xlabel("Number of CSPs")
    plt.ylabel("Time (s)")
    plt.title("Impact of CSP count on latency")
    plt.legend()
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.tight_layout()
    plt.savefig(output_path, dpi=200)
    plt.close()


def annotate_query_results(results: List[dict], mode: str) -> List[dict]:
    annotated = []
    for item in results:
        tokens = item.get("tokens", [])
        dummy = sum(1 for typ, tok in tokens if typ == "kw" and tok.startswith("DUMMY"))
        annotated.append({
            "scenario": item["scenario"],
            "mode": mode,
            "plan_time": item["plan_time"],
            "server_time": item["server_time"],
            "client_time": item["client_time"],
            "total_time": item["total_time"],
            "token_count": item["token_count"],
            "dummy_tokens": dummy,
            "hits": item["hits"],
        })
    return annotated


def main() -> None:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    plt.style.use("seaborn-v0_8-colorblind")

    cfg = load_config(str(CONFIG_PATH))
    dataset = load_dataset(DATA_CSV)
    max_size = len(dataset)

    sizes = [s for s in [500, 1000, 2000, 4000, 8000, max_size] if s <= max_size]
    index_data = measure_index_scaling(cfg, dataset, sizes)

    subset_size = min(8000, max_size)
    aui_full, keys_full = build_index(dataset[:subset_size], cfg)

    queries = [
        ("Single keyword", "ORLANDO"),
        ("Multi keyword", "ORLANDO ENGINEERING UNIVERSITY"),
        ("Long query", "ENGINEERING BUSINESS ADMINISTRATION COLLEGE PROGRAM"),
        ("Spatio-temporal", "ORLANDO ENGINEERING ; R: 28.3,-81.5,28.7,-81.2"),
    ]

    baseline_metrics = []
    suppressed_metrics = []
    for label, query_text in queries:
        base_res = measure_query(query_text, cfg, aui_full, keys_full)
        base_res["scenario"] = label
        baseline_metrics.append(base_res)

        padded_query = apply_padding(query_text, cfg.get("suppression"))
        pad_res = measure_query(padded_query, cfg, aui_full, keys_full)
        pad_res["scenario"] = label
        suppressed_metrics.append(pad_res)

    party_values = [1, 2, 3, 4]
    party_metrics = measure_party_scaling(cfg, dataset, subset_size, queries[1][1], party_values)

    experiments_summary = {
        "index_scaling": index_data,
        "query_latency": {
            "baseline": annotate_query_results(baseline_metrics, "baseline"),
            "suppressed": annotate_query_results(suppressed_metrics, "suppressed"),
        },
        "party_scaling": party_metrics,
    }

    with open(RESULT_DIR / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(experiments_summary, f, indent=2, ensure_ascii=False)

    plot_index_scaling(index_data, FIG_DIR / "index_scaling.png")
    plot_query_latency(baseline_metrics, suppressed_metrics, FIG_DIR / "query_latency.png")
    plot_party_scaling(party_metrics, FIG_DIR / "party_scaling.png")

    print("Experiment metrics written to", RESULT_DIR / "metrics.json")
    print("Figures saved under", FIG_DIR)


if __name__ == "__main__":
    main()
