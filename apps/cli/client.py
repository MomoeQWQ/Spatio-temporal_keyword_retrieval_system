import argparse
import os
import sys

# Ensure project root on sys.path
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, '..', '..'))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from apps.cli.runtime_utils import http_post, login_and_get_token
from core.config_loader import load_config
from core.secure_search import (
    build_candidate_index_from_csv,
    prepare_query_plan,
    prepare_query_plan_with_expansion,
    combine_csp_responses,
    decrypt_matches,
    rank_results_by_priority,
    run_fast_preview_verification,
    run_fx_hmac_verification,
    select_sentinel_positions,
)
from core.secure_search.indexing import load_index_artifacts


def run_one_plan(
    plan,
    csp_endpoints,
    auth_token: str,
    aui: dict,
    keys: tuple,
    *,
    candidate_positions=None,
    sentinel_positions=None,
    verify_enabled: bool = True,
    preview_verify_enabled: bool = False,
):
    responses = []
    for party_id, base in enumerate(csp_endpoints):
        body = {
            'party_id': party_id,
            'tokens': plan.payloads[party_id],
            'security_param': plan.security_param,
            'auth_token': auth_token,
        }
        if candidate_positions is not None:
            body['candidate_positions'] = list(candidate_positions)
        if sentinel_positions is not None:
            body['sentinel_positions'] = list(sentinel_positions)
        responses.append(http_post(base + '/eval', body))
    combined_vecs, combined_proofs = combine_csp_responses(plan, responses, aui)
    _, hits = decrypt_matches(
        plan,
        combined_vecs,
        aui,
        keys,
        candidate_positions=(list(candidate_positions) if candidate_positions is not None else None),
    )
    preview_ok = True
    if preview_verify_enabled:
        preview_ok, _ = run_fast_preview_verification(
            plan,
            responses,
            aui,
            keys,
            candidate_positions=(list(candidate_positions) if candidate_positions is not None else None),
            sentinel_positions=(list(sentinel_positions) if sentinel_positions is not None else None),
        )
    ok_verify = (
        run_fx_hmac_verification(plan, combined_vecs, combined_proofs, aui, keys)
        if verify_enabled
        else True
    )
    return preview_ok, ok_verify, hits


def _source_label(base_hit: bool, source_hits: int) -> str:
    if source_hits <= 0:
        return "none"
    if base_hit and source_hits == 1:
        return "base"
    if base_hit:
        return f"base+{source_hits - 1}exp"
    return f"{source_hits}exp"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--csp', nargs='+', default=['http://127.0.0.1:8001', 'http://127.0.0.1:8002', 'http://127.0.0.1:8003'])
    ap.add_argument('--query', type=str, default=None)
    ap.add_argument('--aui', type=str, default=os.path.join(THIS_DIR, 'aui.pkl'))
    ap.add_argument('--keys', type=str, default=os.path.join(THIS_DIR, 'K.pkl'))
    ap.add_argument('--config', type=str, default=os.path.join(PROJ_ROOT, 'conFig.ini'))
    ap.add_argument('--username', type=str, default='alice')
    ap.add_argument('--password', type=str, default='alice123')
    ap.add_argument('--auth-token', type=str, default=None, help='pre-obtained auth token')
    ap.add_argument('--token-ttl', type=int, default=3600)
    ap.add_argument('--expansion-mode', choices=['none', 'fallback', 'gemini'], default='fallback')
    ap.add_argument('--retrieval-mode', choices=['legacy', 'rapq', 'rapq_plus'], default='legacy')
    ap.add_argument('--rapq-max-candidates', type=int, default=0, help='0 means unlimited')
    ap.add_argument('--rapq-sentinels', type=int, default=8, help='number of non-candidate rows to audit in rapq_plus mode')
    ap.add_argument('--disable-verify', action='store_true', help='skip FX+HMAC verification')
    ap.add_argument('--max-expansion-terms', type=int, default=5)
    ap.add_argument('--top-k', type=int, default=20)
    ap.add_argument('--dataset', type=str, default=os.path.join(PROJ_ROOT, 'us-colleges-and-universities.csv'))
    args = ap.parse_args()

    cfg = load_config(args.config)
    aui, keys = load_index_artifacts(args.aui, args.keys)

    query_in = args.query or (sys.argv[1] if len(sys.argv) > 1 else input("Enter query (kw; optional R): "))
    auth_token = args.auth_token or login_and_get_token(args.csp[0], args.username, args.password, ttl_seconds=args.token_ttl)

    llm_callable = None
    expanded = None
    if args.expansion_mode == 'gemini':
        try:
            from core.ai_clients import make_gemini_llm

            llm_callable = make_gemini_llm()
            print("[client] Expansion backend: Gemini")
        except Exception as exc:
            print(f"[client] Gemini unavailable ({exc}); fallback expansion will be used.")

    if args.expansion_mode == 'none':
        plans = [prepare_query_plan(query_in, aui, cfg)]
    else:
        expanded = prepare_query_plan_with_expansion(
            query_in,
            aui,
            cfg,
            llm_callable=llm_callable,
            max_terms=args.max_expansion_terms,
        )
        plans = expanded.plans
        print(f"[client] Expansion added tokens: {expanded.expansion.added_tokens}")
        print(f"[client] Subqueries: {len(plans)}")

    if not plans:
        raise RuntimeError("no query plans generated")
    if len(args.csp) != plans[0].num_parties:
        raise ValueError(f"Expected {plans[0].num_parties} CSP endpoints, got {len(args.csp)}")

    candidate_index = None
    if args.retrieval_mode in ('rapq', 'rapq_plus'):
        print("[client] Building RAPQ candidate index...")
        candidate_index = build_candidate_index_from_csv(args.dataset, cfg)
        print(f"[client] RAPQ index ready: {candidate_index.n_records} records")

    verify_enabled = not args.disable_verify
    if args.retrieval_mode == 'rapq' and verify_enabled:
        # RAPQ returns candidate-pruned vectors; full-chain proof verification is not applicable.
        verify_enabled = False
        print("[client] RAPQ mode: FX+HMAC full verification skipped (use legacy mode for strict verification).")
    preview_verify_enabled = False
    if args.retrieval_mode == 'rapq_plus':
        preview_verify_enabled = True
        if verify_enabled:
            verify_enabled = False
            print("[client] RAPQ+ mode: running fast preview verification only (use legacy mode for strict FX+HMAC verification).")

    all_verify_ok = True
    all_preview_ok = True
    union_hits = set()
    hit_sources = {}
    candidate_sizes = []
    sentinel_sizes = []
    for idx, plan in enumerate(plans):
        candidate_positions = None
        sentinel_positions = None
        if candidate_index is not None:
            selection = candidate_index.select_candidates(
                plan.query,
                cfg,
                max_candidates=(None if args.rapq_max_candidates <= 0 else args.rapq_max_candidates),
            )
            candidate_positions = selection.positions
            candidate_sizes.append(len(candidate_positions))
            print(
                f"[client][RAPQ] subquery#{idx + 1}: "
                f"candidates={len(candidate_positions)}/{selection.total_records} "
                f"({selection.candidate_ratio:.2%})"
            )
            if args.retrieval_mode == 'rapq_plus':
                sentinel_positions = select_sentinel_positions(
                    selection.total_records,
                    candidate_positions,
                    args.rapq_sentinels,
                    seed_material=f"{plan.query}|{idx}|{args.username}",
                )
                sentinel_sizes.append(len(sentinel_positions))
                print(f"[client][RAPQ+] subquery#{idx + 1}: sentinels={len(sentinel_positions)}")
        preview_ok, ok_verify, hits = run_one_plan(
            plan,
            args.csp,
            auth_token,
            aui,
            keys,
            candidate_positions=candidate_positions,
            sentinel_positions=sentinel_positions,
            verify_enabled=verify_enabled,
            preview_verify_enabled=preview_verify_enabled,
        )
        all_preview_ok = all_preview_ok and preview_ok
        all_verify_ok = all_verify_ok and ok_verify
        for hid in hits:
            union_hits.add(hid)
            hit_sources.setdefault(str(hid), set()).add(idx)

    if preview_verify_enabled:
        print(f"[client] Preview verify: {'pass' if all_preview_ok else 'fail'}")
    if verify_enabled:
        print(f"[client] Verify: {'pass' if all_verify_ok else 'fail'}")
    else:
        print("[client] Verify: skipped")
    print(f"[client] Matches: {len(union_hits)}")
    if candidate_sizes:
        avg_cand = sum(candidate_sizes) / max(len(candidate_sizes), 1)
        print(f"[client][RAPQ] Avg candidates/subquery: {avg_cand:.1f}")
    if sentinel_sizes:
        avg_sent = sum(sentinel_sizes) / max(len(sentinel_sizes), 1)
        print(f"[client][RAPQ+] Avg sentinels/subquery: {avg_sent:.1f}")

    import pandas as pd

    raw_df = pd.read_csv(args.dataset, sep=';')
    view = raw_df[raw_df['IPEDSID'].astype(str).isin([str(x) for x in union_hits])]
    ranked = rank_results_by_priority(
        query_in,
        view.to_dict('records'),
        expanded_tokens=(expanded.expansion.expanded_tokens if expanded is not None else None),
        hit_sources=hit_sources,
    )
    for idx, item in enumerate(ranked[: max(args.top_k, 1)], 1):
        row = item['record']
        source_tag = _source_label(bool(item['base_hit']), int(item['source_hits']))
        print(
            f"{idx}. [{row['IPEDSID']}] {row['NAME']} - {row['ADDRESS']}, {row['CITY']}, {row['STATE']}  "
            f"({row.get('Geo Point', '')}) | score={item['score']:.2f} | source={source_tag}"
        )


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f"[client] Error: {exc}")
        raise SystemExit(1)
