"""Client-side query planning and result handling utilities."""

from __future__ import annotations

import base64
import math
from dataclasses import dataclass
from typing import List, Tuple

from QueryUtils import tokenize_normalized
from GBF import fingerprint
from SetupProcess import F
from verification import verify_fx_hmac
from DMPF import Gen
from .native_accel import xor_bytes, xor_pair_lists


def _hash_pos(item: str, size: int, k: int) -> List[int]:
    import hashlib
    h1 = int(hashlib.sha256(item.encode('utf-8')).hexdigest(), 16)
    h2 = int(hashlib.md5(item.encode('utf-8')).hexdigest(), 16)
    return [(h1 + i * h2) % size for i in range(k)]


def _prp(zeta: bytes, x: int) -> int:
    import hashlib
    return int(hashlib.sha256(zeta + x.to_bytes(8, 'big')).hexdigest(), 16)


def _cuckoo_bucketize(indices: List[int], m: int, kappa: int, M: int, zeta: bytes) -> dict:
    buckets = {b: [] for b in range(max(M, 1))}
    for j in indices:
        cands = []
        for i in range(kappa):
            val = _prp(zeta, j + m * i)
            b = val % max(M, 1)
            cands.append(b)
        best = min(cands, key=lambda b: len(buckets[b]))
        buckets[best].append(j)
    return {b: lst for b, lst in buckets.items() if lst}


@dataclass
class QueryPlan:
    query: str
    tokens: List[Tuple[str, str]]
    payloads: List[List[dict]]
    keyword_tokens: List[str]
    spatial_tokens: List[str]
    security_param: int
    num_parties: int


def _extract_spatial_cells(query_text: str, config: dict) -> List[str]:
    cells: List[str] = []
    if 'R:' not in query_text:
        return cells
    try:
        _, rng = query_text.split('R:', 1)
        parts = rng.replace(';', ' ').replace(',', ' ').split()
        if len(parts) < 4:
            return cells
        lat_min, lon_min, lat_max, lon_max = map(float, parts[:4])
        grid = config.get("spatial_grid", {})
        lat_step = float(grid.get("cell_size_lat", 0.5))
        lon_step = float(grid.get("cell_size_lon", 0.5))
        r0 = math.floor(lat_min / lat_step)
        r1 = math.floor(lat_max / lat_step)
        c0 = math.floor(lon_min / lon_step)
        c1 = math.floor(lon_max / lon_step)
        for r in range(min(r0, r1), max(r0, r1) + 1):
            for c in range(min(c0, c1), max(c0, c1) + 1):
                cells.append(f"CELL:R{r}_C{c}")
    except Exception:
        return []
    return cells


def prepare_query_plan(query_text: str, aui: dict, config: dict) -> QueryPlan:
    kw_text = query_text.split('R:', 1)[0] if 'R:' in query_text else query_text
    tokens_kw = tokenize_normalized(kw_text)
    spatial_cells = _extract_spatial_cells(query_text, config)
    tokens_all = [("kw", t) for t in (tokens_kw or [query_text])]
    tokens_all += [("spa", c) for c in spatial_cells]

    U = int(aui["U"])
    lam = int(aui["security_param"])
    m1 = int(aui["m1"])
    m2 = int(aui["m2"])
    k_tex = int(aui.get("k_tex", 4))
    k_spa = int(aui.get("k_spa", 3))
    ck_kw = aui.get("cuckoo_kw", {"kappa": 3, "load": 1.27, "seed": "cuckoo-seed"})
    ck_spa = aui.get("cuckoo_spa", {"kappa": 3, "load": 1.27, "seed": "cuckoo-seed-spa"})

    per_party = [[{"type": typ, "buckets": []} for typ, _ in tokens_all] for _ in range(U)]

    for tok_idx, (typ, tok) in enumerate(tokens_all):
        if typ == 'kw':
            S = _hash_pos(tok, m2, k_tex)
            kappa = min(int(ck_kw.get("kappa", 3)), k_tex)
            load = float(ck_kw.get("load", 1.27))
            zeta = str(ck_kw.get('seed', 'cuckoo-seed')).encode('utf-8')
            m = m2
        else:
            S = _hash_pos(tok, m1, k_spa)
            kappa = min(int(ck_spa.get("kappa", 3)), k_spa)
            load = float(ck_spa.get("load", 1.27))
            zeta = str(ck_spa.get('seed', 'cuckoo-seed-spa')).encode('utf-8')
            m = m1
        bucket_count = max(1, int(math.ceil(load * max(1, len(S)))))
        buckets = _cuckoo_bucketize(S, m, kappa, bucket_count, zeta)
        for cols in buckets.values():
            if not cols:
                continue
            domain = list(range(len(cols)))
            keys = Gen(lam, domain, len(domain), num_parties=U)
            for party in range(U):
                bits = [int(keys[party]["bits"].get(j, 0)) for j in domain]
                per_party[party][tok_idx]['buckets'].append({
                    'columns': cols,
                    'bits': bits,
                })

    return QueryPlan(
        query=query_text,
        tokens=tokens_all,
        payloads=per_party,
        keyword_tokens=tokens_kw,
        spatial_tokens=spatial_cells,
        security_param=lam,
        num_parties=U,
    )


def combine_csp_responses(plan: QueryPlan, responses: List[dict], aui: dict) -> Tuple[List[List[bytes]], List[bytes]]:
    lam = int(aui["security_param"])
    n = len(aui["ids"])
    byte_len = int(aui["segment_length"])
    token_count = len(plan.tokens)

    def _decode(blob: str) -> bytes:
        return base64.b64decode(blob.encode('utf-8'))

    combined_vecs: List[List[bytes]] = []
    combined_proofs: List[bytes] = []

    for t_idx in range(token_count):
        vec = [b"\x00" * byte_len for _ in range(n)]
        proof = b"\x00" * lam
        for resp in responses:
            token_vecs = resp["result_shares"][t_idx]
            token_proof = resp["proof_shares"][t_idx]
            decoded_vecs = [_decode(blob) for blob in token_vecs]
            vec = xor_pair_lists(vec, decoded_vecs)
            proof = xor_bytes(proof, _decode(token_proof))
        combined_vecs.append(vec)
        combined_proofs.append(proof)

    return combined_vecs, combined_proofs


def decrypt_matches(plan: QueryPlan, combined_vecs: List[List[bytes]], aui: dict, keys: tuple) -> Tuple[List[bool], List]:
    Ke, _, _ = keys
    m1 = int(aui["m1"])
    m2 = int(aui["m2"])
    n = len(aui["ids"])
    byte_len = int(aui["segment_length"])
    k_tex = int(aui.get("k_tex", 4))
    k_spa = int(aui.get("k_spa", 3))

    def pad_for_obj(idx1: int, obj_id) -> bytes:
        total_len = (m1 + m2) * byte_len
        return F(Ke, (str(idx1) + str(obj_id)).encode('utf-8'), total_len)

    matches = [True] * n
    for t_idx, (typ, tok) in enumerate(plan.tokens):
        if typ != 'kw':
            continue
        S = _hash_pos(tok, m2, k_tex)
        fp = fingerprint(tok, byte_len * 8)
        for row_idx, obj_id in enumerate(aui["ids"], start=1):
            enc_vec = combined_vecs[t_idx][row_idx - 1]
            pad = pad_for_obj(row_idx, obj_id)
            pad_acc = b"\x00" * byte_len
            for j in S:
                start = (m1 + j) * byte_len
                pad_acc = xor_bytes(pad_acc, pad[start:start + byte_len])
            plain = xor_bytes(enc_vec, pad_acc)
            matches[row_idx - 1] &= (plain == fp)

    spatial_ok = [False] * n if plan.spatial_tokens else [True] * n
    base_idx = len(plan.keyword_tokens or [plan.query])
    for s_off, cell in enumerate(plan.spatial_tokens):
        S = _hash_pos(cell, m1, k_spa)
        fp = fingerprint(cell, byte_len * 8)
        t_idx = base_idx + s_off
        for row_idx, obj_id in enumerate(aui["ids"], start=1):
            enc_vec = combined_vecs[t_idx][row_idx - 1]
            pad = pad_for_obj(row_idx, obj_id)
            pad_acc = b"\x00" * byte_len
            for j in S:
                start = j * byte_len
                pad_acc = xor_bytes(pad_acc, pad[start:start + byte_len])
            plain = xor_bytes(enc_vec, pad_acc)
            if plain == fp:
                spatial_ok[row_idx - 1] = True

    final_ok = [matches[i] and spatial_ok[i] for i in range(n)]
    hits = [aui["ids"][i] for i, ok in enumerate(final_ok) if ok]
    return final_ok, hits


def run_fx_hmac_verification(plan: QueryPlan, combined_vecs: List[List[bytes]], combined_proofs: List[bytes], aui: dict, keys: tuple) -> bool:
    tokens_override = [tok for _, tok in plan.tokens]
    return verify_fx_hmac(
        plan.query,
        aui,
        keys,
        combined_vecs,
        combined_proofs,
        tokens_override=tokens_override,
    )
