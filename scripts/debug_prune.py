from __future__ import annotations

import base64
import sys
from pathlib import Path
import warnings

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config_loader import load_config
import prepare_dataset
from convert_dataset import convert_dataset
from SetupProcess import Setup
from secure_search import combine_csp_responses, decrypt_matches, prepare_query_plan
from ai_pruning import PruningModel, should_query_cell


def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def simulate_csp(aui: dict, payload):
    lam = int(aui["security_param"])
    byte_len = int(aui["segment_length"])
    n = len(aui["ids"])
    shares = []
    proofs = []
    for token in payload:
        vec = [b"\x00" * byte_len for _ in range(n)]
        proof = b"\x00" * lam
        mat = aui["I_tex"] if token["type"] == "kw" else aui["I_spa"]
        matrix = mat["EbW" if token["type"] == "kw" else "Ebp"]
        sigma = mat["sigma"]
        for bucket in token["buckets"]:
            for idx, col in enumerate(bucket["columns"]):
                if bucket["bits"][idx]:
                    column_cells = [row[col] for row in matrix]
                    for i in range(n):
                        vec[i] = bytes_xor(vec[i], column_cells[i])
                    proof = bytes_xor(proof, sigma[col])
        shares.append([base64.b64encode(v).decode() for v in vec])
        proofs.append(base64.b64encode(proof).decode())
    return {"result_shares": shares, "proof_shares": proofs}


def prune_plan(plan, model):
    keyword_tokens = [tok for typ, tok in plan.tokens if typ == "kw"]
    keep_mask = []
    for typ, tok in plan.tokens:
        keep_mask.append(True if typ != "spa" else should_query_cell(model, tok, keyword_tokens))
    for party in plan.payloads:
        for entry, keep in zip(party, keep_mask):
            if entry["type"] == "spa" and not keep:
                entry["buckets"] = []
    return plan


def run(query, cfg, aui, keys, model):
    plan = prepare_query_plan(query, aui, cfg)
    plan = prune_plan(plan, model)
    responses = [simulate_csp(aui, plan.payloads[p]) for p in range(plan.num_parties)]
    combined_vecs, combined_proofs = combine_csp_responses(plan, responses, aui)
    print(query)
    print('  tokens', len(plan.tokens), 'vecs', len(combined_vecs))
    decrypt_matches(plan, combined_vecs, aui, keys)


def main():
    msg = "scripts/debug_prune.py is deprecated. Prefer scripts/benchmark_pruning.py."
    print(f"[deprecated] {msg}", file=sys.stderr)
    warnings.warn(msg, FutureWarning, stacklevel=2)
    cfg = load_config('conFig.ini')
    dict_list = prepare_dataset.load_and_transform('us-colleges-and-universities.csv')[:500]
    db = convert_dataset(dict_list, cfg)
    aui, keys = Setup(db, cfg)
    model = PruningModel('ai_pruning/model.txt')
    queries = [
        "ORLANDO UNIVERSITY; R: 28.2,-81.6,28.8,-81.1",
        "ENGINEERING COLLEGE; R: 27.5,-82.0,28.5,-80.5",
    ]
    for q in queries:
        run(q, cfg, aui, keys, model)

if __name__ == '__main__':
    main()
