"""Evaluate query expansion effectiveness on sampled queries."""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import sys
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config_loader import load_config
from core import prepare_dataset
from core.convert_dataset import convert_dataset
from core.SetupProcess import Setup
from core.QueryUtils import tokenize_normalized
from core.secure_search import combine_csp_responses, decrypt_matches, prepare_query_plan
from core.secure_search.expansion_client import prepare_query_plan_with_expansion
from core.secure_search.query_expansion import expand_query_keywords

DATA_LIMIT = 3000
TOP_K = 10
OUTPUT_DIR = ROOT / "evaluation" / "outputs" / "query_expansion"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class QueryEvaluation:
    query: str
    baseline_hits: List[int]
    expanded_hits: List[int]
    incremental_hits: List[int]
    subquery_count: int
    baseline_latency: float
    expanded_latency: float
    baseline_recall: float
    baseline_precision: float
    baseline_topk: float
    expanded_recall: float
    expanded_precision: float
    expanded_topk: float


def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def simulate_csp(aui: dict, payload: List[dict]) -> dict:
    lam = int(aui["security_param"])
    byte_len = int(aui["segment_length"])
    n = len(aui["ids"])
    result_shares: List[List[str]] = []
    proof_shares: List[str] = []
    for token in payload:
        typ = token["type"]
        buckets = token["buckets"]
        vec = [b"\x00" * byte_len for _ in range(n)]
        proof = b"\x00" * lam
        mat = aui["I_tex"] if typ == "kw" else aui["I_spa"]
        matrix = mat["EbW" if typ == "kw" else "Ebp"]
        sigma = mat["sigma"]
        for bucket in buckets:
            cols = bucket["columns"]
            bits = bucket["bits"]
            for local_idx, col_idx in enumerate(cols):
                if bits[local_idx]:
                    column_cells = [row[col_idx] for row in matrix]
                    for i in range(n):
                        vec[i] = bytes_xor(vec[i], column_cells[i])
                    proof = bytes_xor(proof, sigma[col_idx])
        result_shares.append([base64.b64encode(v).decode("ascii") for v in vec])
        proof_shares.append(base64.b64encode(proof).decode("ascii"))
    return {"result_shares": result_shares, "proof_shares": proof_shares}


def run_secure_query(plan, aui, keys) -> List[int]:
    responses = [simulate_csp(aui, plan.payloads[party_id]) for party_id in range(plan.num_parties)]
    combined_vecs, combined_proofs = combine_csp_responses(plan, responses, aui)
    _, hits = decrypt_matches(plan, combined_vecs, aui, keys)
    return hits


def record_tokens_map(df: pd.DataFrame) -> Dict[int, Set[str]]:
    tokens_map: Dict[int, Set[str]] = {}
    for _, row in df.iterrows():
        text = " ".join(str(row[col]) for col in ["NAME", "ADDRESS", "CITY", "STATE"] if col in df.columns)
        tokens_map[int(row["IPEDSID"])] = set(tokenize_normalized(text))
    return tokens_map


def build_truth(tokens_map: Dict[int, Set[str]], groups: List[Sequence[str]]) -> Set[int]:
    truth: Set[int] = set()
    for record_id, token_set in tokens_map.items():
        if all(any(term in token_set for term in group) for group in groups):
            truth.add(record_id)
    return truth


def compute_metrics(hits: Sequence[int], truth: Set[int], top_k: int) -> Tuple[float, float, float]:
    hits_set = set(hits)
    if not truth:
        recall = 1.0
    else:
        recall = len(hits_set & truth) / len(truth)
    if hits:
        precision = len(hits_set & truth) / len(hits)
    else:
        precision = 1.0 if not truth else 0.0
    if hits:
        top = list(hits)[:top_k]
        if truth:
            topk = len(set(top) & truth) / min(top_k, len(truth))
        else:
            topk = 1.0
    else:
        topk = 1.0 if not truth else 0.0
    return recall, precision, topk


def evaluate_queries():
    cfg = load_config("conFig.ini")
    dict_list = prepare_dataset.load_and_transform("us-colleges-and-universities.csv")[:DATA_LIMIT]
    db = convert_dataset(dict_list, cfg)
    aui, keys = Setup(db, cfg)

    df_raw = pd.read_csv("us-colleges-and-universities.csv", sep=";").head(DATA_LIMIT)
    tokens_map = record_tokens_map(df_raw)

    queries = [
        "ORLANDO UNIVERSITY; R: 28.2,-81.6,28.8,-81.1",
        "ENGINEERING COLLEGE; R: 27.5,-82.0,28.5,-80.5",
        "MIAMI MEDICAL; R: 25.7,-80.5,26.4,-80.0",
        "CALIFORNIA TECHNOLOGY; R: 33.5,-118.5,38.0,-121.0",
        "BOSTON BUSINESS; R: 41.8,-71.3,43.2,-70.6",
        "NEW YORK UNIVERSITY; R: 40.4,-74.3,41.0,-73.6",
        "LOS ANGELES COLLEGE; R: 33.5,-118.7,34.3,-117.5",
        "SEATTLE TECHNOLOGY; R: 47.2,-122.6,47.9,-122.0",
        "AUSTIN BUSINESS; R: 29.9,-98.0,30.6,-97.2",
        "CHICAGO MEDICAL; R: 41.4,-88.0,42.1,-87.3",
    ]

    evaluations: List[QueryEvaluation] = []

    for query in queries:
        print(f"Processing query: {query}")
        start = time.perf_counter()
        baseline_plan = prepare_query_plan(query, aui, cfg)
        baseline_hits = run_secure_query(baseline_plan, aui, keys)
        baseline_time = time.perf_counter() - start

        keyword_segment = query.split("R:", 1)[0] if "R:" in query else query
        keyword_tokens = tokenize_normalized(keyword_segment)
        baseline_truth = build_truth(tokens_map, [[token] for token in keyword_tokens])

        start = time.perf_counter()
        expanded_plan = prepare_query_plan_with_expansion(query, aui, cfg)
        expanded_hits_union: Set[int] = set()
        subquery_hits: List[Set[int]] = []
        for plan in expanded_plan.plans:
            hits = set(run_secure_query(plan, aui, keys))
            subquery_hits.append(hits)
            expanded_hits_union.update(hits)
        expanded_time = time.perf_counter() - start

        expansion = expand_query_keywords(keyword_tokens)
        option_groups: List[Sequence[str]] = []
        for token in expansion.original_tokens:
            group = [token]
            group.extend(expansion.token_expansions.get(token, []))
            option_groups.append(group)
        expanded_truth = build_truth(tokens_map, option_groups) if option_groups else set()

        baseline_recall, baseline_precision, baseline_topk = compute_metrics(baseline_hits, baseline_truth, TOP_K)
        expanded_recall, expanded_precision, expanded_topk = compute_metrics(expanded_hits_union, expanded_truth, TOP_K)

        incremental = sorted(expanded_hits_union.difference(baseline_hits))

        evaluations.append(QueryEvaluation(
            query=query,
            baseline_hits=list(baseline_hits),
            expanded_hits=list(expanded_hits_union),
            incremental_hits=incremental,
            subquery_count=len(expanded_plan.plans),
            baseline_latency=baseline_time,
            expanded_latency=expanded_time,
            baseline_recall=baseline_recall,
            baseline_precision=baseline_precision,
            baseline_topk=baseline_topk,
            expanded_recall=expanded_recall,
            expanded_precision=expanded_precision,
            expanded_topk=expanded_topk,
        ))

    df_eval = pd.DataFrame([e.__dict__ for e in evaluations])
    df_eval.to_csv(OUTPUT_DIR / "expansion_metrics.csv", index=False)

    avg_baseline = {
        "Recall": df_eval["baseline_recall"].mean(),
        "Precision": df_eval["baseline_precision"].mean(),
        f"Top@{TOP_K}": df_eval["baseline_topk"].mean(),
        "Latency (s)": df_eval["baseline_latency"].mean(),
    }
    avg_expanded = {
        "Recall": df_eval["expanded_recall"].mean(),
        "Precision": df_eval["expanded_precision"].mean(),
        f"Top@{TOP_K}": df_eval["expanded_topk"].mean(),
        "Latency (s)": df_eval["expanded_latency"].mean(),
    }

    print("\nAverage metrics:")
    print("Baseline:")
    for name, value in avg_baseline.items():
        print(f"  {name}: {value:.4f}")
    print("Expanded:")
    for name, value in avg_expanded.items():
        print(f"  {name}: {value:.4f}")

    print("\nIncremental hits per query:")
    for idx, row in df_eval.iterrows():
        print(f"  {row['query']} -> +{len(row['incremental_hits'])} new IDs")

    methods = ["Baseline", "Expanded"]
    recalls = [avg_baseline["Recall"], avg_expanded["Recall"]]
    precisions = [avg_baseline["Precision"], avg_expanded["Precision"]]
    topks = [avg_baseline[f"Top@{TOP_K}"], avg_expanded[f"Top@{TOP_K}"]]
    latencies = [avg_baseline["Latency (s)"], avg_expanded["Latency (s)"]]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    x = np.arange(len(methods))
    width = 0.25
    axes[0].bar(x - width, recalls, width, label="Recall")
    axes[0].bar(x, precisions, width, label="Precision")
    axes[0].bar(x + width, topks, width, label=f"Top@{TOP_K}")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(methods)
    axes[0].set_ylim(0, 1.05)
    axes[0].set_title("Quality Metrics")
    axes[0].legend()

    axes[1].bar(methods, latencies, color=["tab:blue", "tab:orange"])
    axes[1].set_title("Average Latency (s)")

    fig.tight_layout()
    fig.savefig(OUTPUT_DIR / "expansion_metrics.png")

    fig2, ax2 = plt.subplots(figsize=(10, 4))
    increments = [len(lst) for lst in df_eval['incremental_hits']]
    ax2.bar(range(len(queries)), increments)
    ax2.set_xticks(range(len(queries)))
    ax2.set_xticklabels([f"Q{i+1}" for i in range(len(queries))], rotation=30)
    ax2.set_ylabel("Additional hits")
    ax2.set_title("Incremental hits per query")
    fig2.tight_layout()
    fig2.savefig(OUTPUT_DIR / "incremental_hits.png")


if __name__ == "__main__":
    evaluate_queries()
