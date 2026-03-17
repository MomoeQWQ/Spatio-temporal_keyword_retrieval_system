import argparse
import json
import os
import sys
import urllib.request
import urllib.error

# Ensure project root on sys.path
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, '..'))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from config_loader import load_config
from secure_search import (
    prepare_query_plan,
    prepare_query_plan_with_expansion,
    combine_csp_responses,
    decrypt_matches,
    rank_results_by_priority,
    run_fx_hmac_verification,
)
from secure_search.indexing import load_index_artifacts


def http_post(url: str, obj: dict) -> dict:
    data = json.dumps(obj).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            return json.loads(body.decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        try:
            parsed = json.loads(body)
            msg = parsed.get('error', body)
        except Exception:
            msg = body or str(e)
        raise RuntimeError(f"POST {url} failed ({e.code}): {msg}") from e


def login_and_get_token(csp_base: str, username: str, password: str, ttl_seconds: int = 3600) -> str:
    resp = http_post(
        csp_base + '/auth/login',
        {'username': username, 'password': password, 'ttl_seconds': ttl_seconds},
    )
    token = str(resp.get('auth_token', '')).strip()
    if not token:
        raise RuntimeError("login succeeded but no auth_token was returned")
    return token


def run_one_plan(plan, csp_endpoints, auth_token: str, aui: dict, keys: tuple):
    responses = []
    for party_id, base in enumerate(csp_endpoints):
        body = {
            'party_id': party_id,
            'tokens': plan.payloads[party_id],
            'security_param': plan.security_param,
            'auth_token': auth_token,
        }
        responses.append(http_post(base + '/eval', body))
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
    ap.add_argument('--max-expansion-terms', type=int, default=5)
    ap.add_argument('--top-k', type=int, default=20)
    args = ap.parse_args()

    cfg = load_config(args.config)
    aui, keys = load_index_artifacts(args.aui, args.keys)

    query_in = args.query or (sys.argv[1] if len(sys.argv) > 1 else input("Enter query (kw; optional R): "))
    auth_token = args.auth_token or login_and_get_token(args.csp[0], args.username, args.password, ttl_seconds=args.token_ttl)

    llm_callable = None
    expanded = None
    if args.expansion_mode == 'gemini':
        try:
            from ai_clients import make_gemini_llm

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

    all_verify_ok = True
    union_hits = set()
    hit_sources = {}
    for idx, plan in enumerate(plans):
        ok_verify, hits = run_one_plan(plan, args.csp, auth_token, aui, keys)
        all_verify_ok = all_verify_ok and ok_verify
        for hid in hits:
            union_hits.add(hid)
            hit_sources.setdefault(str(hid), set()).add(idx)

    print(f"[client] Verify: {'pass' if all_verify_ok else 'fail'}")
    print(f"[client] Matches: {len(union_hits)}")

    import pandas as pd

    raw_df = pd.read_csv(os.path.join(PROJ_ROOT, 'us-colleges-and-universities.csv'), sep=';')
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
