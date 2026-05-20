"""Demonstration of LLM-based query expansion integrated with secure search."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import random

from core.config_loader import load_config
from core import prepare_dataset
from core.convert_dataset import convert_dataset
from core.SetupProcess import Setup
from core.secure_search import combine_csp_responses, decrypt_matches
from core.secure_search.expansion_client import prepare_query_plan_with_expansion

try:
    from core.ai_clients import make_gemini_llm
except ImportError:  # pragma: no cover
    make_gemini_llm = None


def dummy_llm(prompt: str) -> str:
    prompt_lower = prompt.lower()
    if "university" in prompt_lower:
        return "college, campus, institute"
    if "medical" in prompt_lower:
        return "health, hospital, clinical"
    if "business" in prompt_lower:
        return "commerce, enterprise"
    if "engineering" in prompt_lower:
        return "technology, tech"
    return ""


def main():
    cfg = load_config('conFig.ini')
    dict_list = prepare_dataset.load_and_transform('us-colleges-and-universities.csv')[:1000]
    db = convert_dataset(dict_list, cfg)
    aui, keys = Setup(db, cfg)

    query = "MIAMI MEDICAL; R: 25.7,-80.5,26.4,-80.0"

    llm_callable = None
    if make_gemini_llm is not None:
        try:
            llm_callable = make_gemini_llm()
            print("Using Gemini API for query expansion.")
        except Exception as exc:
            print(f"Gemini not available ({exc}); falling back to dummy expansions.")

    if llm_callable is None:
        llm_callable = dummy_llm
        print("Using built-in dummy expansions.")

    expanded = prepare_query_plan_with_expansion(query, aui, cfg, llm_callable=llm_callable)
    print(f"Original query: {query}")
    print(f"Added keywords (OR): {expanded.expansion.added_tokens}")
    print("Generated subqueries:")
    for idx, qtext in enumerate(expanded.query_texts, 1):
        print(f"  {idx}. {qtext}")

    union_hits = set()
    for plan, qtext in zip(expanded.plans, expanded.query_texts):
        responses = [
            {"result_shares": [["AA=="] * len(aui['ids']) for _ in plan.tokens], "proof_shares": ["AA=="] * len(plan.tokens)}
            for _ in range(plan.num_parties)
        ]
        combined_vecs, combined_proofs = combine_csp_responses(plan, responses, aui)
        _, hits = decrypt_matches(plan, combined_vecs, aui, keys)
        union_hits.update(hits)
        print(f"Subquery '{qtext}' -> hits: {len(hits)}")

    print(f"Union hits (unique IDs): {len(union_hits)}")


if __name__ == '__main__':
    main()
