"""Client-side query planning and result handling utilities."""

from __future__ import annotations

import base64
import hashlib
import math
import random
from dataclasses import dataclass
from typing import List, Tuple

from core.QueryUtils import tokenize_normalized
from core.GBF import fingerprint
from core.SetupProcess import F
from core.verification import fast_subset_tag, verify_fx_hmac
from core.DMPF import Gen
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


def select_sentinel_positions(
    total_records: int,
    candidate_positions: List[int] | None,
    sample_size: int,
    *,
    seed_material: str,
) -> List[int]:
    if sample_size <= 0 or total_records <= 0:
        return []
    candidate_set = {int(x) for x in (candidate_positions or []) if 0 <= int(x) < total_records}
    complement = [idx for idx in range(total_records) if idx not in candidate_set]
    if not complement:
        return []
    if sample_size >= len(complement):
        return complement
    seed = int.from_bytes(hashlib.sha256(seed_material.encode("utf-8")).digest()[:8], "big")
    rng = random.Random(seed)
    return sorted(rng.sample(complement, sample_size))


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


def extract_query_tokens(query_text: str, config: dict) -> Tuple[List[str], List[str]]:
    """Extract normalized keyword tokens and spatial grid cells from a query string."""
    kw_text = query_text.split('R:', 1)[0] if 'R:' in query_text else query_text
    keyword_tokens = tokenize_normalized(kw_text)
    spatial_cells = _extract_spatial_cells(query_text, config)
    return keyword_tokens, spatial_cells


def prepare_query_plan(query_text: str, aui: dict, config: dict) -> QueryPlan:
    tokens_kw, spatial_cells = extract_query_tokens(query_text, config)
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


def _decode_b64(blob: str) -> bytes:
    return base64.b64decode(blob.encode('utf-8'))


def combine_sparse_token_vectors(
    plan: QueryPlan,
    responses: List[dict],
    aui: dict,
    *,
    result_field: str,
    positions_field: str,
) -> List[List[bytes]]:
    n = len(aui["ids"])
    byte_len = int(aui["segment_length"])
    token_count = len(plan.tokens)

    positions = None
    if responses:
        first = responses[0]
        if positions_field in first:
            positions = [int(x) for x in first.get(positions_field, [])]
            for resp in responses[1:]:
                rhs = [int(x) for x in resp.get(positions_field, [])]
                if rhs != positions:
                    raise ValueError(f"{positions_field} mismatch across CSP responses")

    if positions is None:
        raise ValueError(f"{positions_field} missing from sparse response")

    combined_vecs: List[List[bytes]] = []
    for t_idx in range(token_count):
        vec = [b"\x00" * byte_len for _ in range(n)]
        for resp in responses:
            token_vecs = resp.get(result_field, [])[t_idx]
            if len(token_vecs) != len(positions):
                raise ValueError(f"{result_field} length does not match {positions_field}")
            for local_idx, row_idx in enumerate(positions):
                if 0 <= row_idx < n:
                    vec[row_idx] = xor_bytes(vec[row_idx], _decode_b64(token_vecs[local_idx]))
        combined_vecs.append(vec)
    return combined_vecs


def combine_csp_responses(plan: QueryPlan, responses: List[dict], aui: dict) -> Tuple[List[List[bytes]], List[bytes]]:
    lam = int(aui["security_param"])
    n = len(aui["ids"])
    byte_len = int(aui["segment_length"])
    token_count = len(plan.tokens)

    combined_vecs: List[List[bytes]] = []
    combined_proofs: List[bytes] = []
    candidate_positions = None
    if responses:
        first = responses[0]
        if "candidate_positions" in first:
            candidate_positions = [int(x) for x in first.get("candidate_positions", [])]
            for resp in responses[1:]:
                rhs = [int(x) for x in resp.get("candidate_positions", [])]
                if rhs != candidate_positions:
                    raise ValueError("candidate_positions mismatch across CSP responses")

    for t_idx in range(token_count):
        vec = [b"\x00" * byte_len for _ in range(n)]
        proof = b"\x00" * lam
        for resp in responses:
            token_vecs = resp["result_shares"][t_idx]
            token_proof = resp["proof_shares"][t_idx]
            if candidate_positions is None:
                decoded_vecs = [_decode_b64(blob) for blob in token_vecs]
                vec = xor_pair_lists(vec, decoded_vecs)
            else:
                if len(token_vecs) != len(candidate_positions):
                    raise ValueError("sparse result_shares length does not match candidate_positions")
                for local_idx, row_idx in enumerate(candidate_positions):
                    if 0 <= row_idx < n:
                        vec[row_idx] = xor_bytes(vec[row_idx], _decode_b64(token_vecs[local_idx]))
            proof = xor_bytes(proof, _decode_b64(token_proof))
        combined_vecs.append(vec)
        combined_proofs.append(proof)

    return combined_vecs, combined_proofs


def decrypt_matches(
    plan: QueryPlan,
    combined_vecs: List[List[bytes]],
    aui: dict,
    keys: tuple,
    candidate_positions: List[int] | None = None,
) -> Tuple[List[bool], List]:
    Ke = keys[0]
    m1 = int(aui["m1"])
    m2 = int(aui["m2"])
    n = len(aui["ids"])
    byte_len = int(aui["segment_length"])
    k_tex = int(aui.get("k_tex", 4))
    k_spa = int(aui.get("k_spa", 3))

    def pad_for_obj(idx1: int, obj_id) -> bytes:
        total_len = (m1 + m2) * byte_len
        return F(Ke, (str(idx1) + str(obj_id)).encode('utf-8'), total_len)

    if candidate_positions is None:
        active_indices = list(range(n))
    else:
        active_indices = sorted({int(i) for i in candidate_positions if 0 <= int(i) < n})
    matches = [False] * n if candidate_positions is not None else [True] * n
    if candidate_positions is not None:
        for idx in active_indices:
            matches[idx] = True

    for t_idx, (typ, tok) in enumerate(plan.tokens):
        if typ != 'kw':
            continue
        S = _hash_pos(tok, m2, k_tex)
        fp = fingerprint(tok, byte_len * 8)
        for rec_idx in active_indices:
            row_idx = rec_idx + 1
            obj_id = aui["ids"][rec_idx]
            enc_vec = combined_vecs[t_idx][rec_idx]
            pad = pad_for_obj(row_idx, obj_id)
            pad_acc = b"\x00" * byte_len
            for j in S:
                start = (m1 + j) * byte_len
                pad_acc = xor_bytes(pad_acc, pad[start:start + byte_len])
            plain = xor_bytes(enc_vec, pad_acc)
            matches[rec_idx] &= (plain == fp)

    spatial_ok = [False] * n
    if not plan.spatial_tokens:
        for rec_idx in active_indices:
            spatial_ok[rec_idx] = True
    base_idx = len(plan.keyword_tokens or [plan.query])
    for s_off, cell in enumerate(plan.spatial_tokens):
        S = _hash_pos(cell, m1, k_spa)
        fp = fingerprint(cell, byte_len * 8)
        t_idx = base_idx + s_off
        for rec_idx in active_indices:
            row_idx = rec_idx + 1
            obj_id = aui["ids"][rec_idx]
            enc_vec = combined_vecs[t_idx][rec_idx]
            pad = pad_for_obj(row_idx, obj_id)
            pad_acc = b"\x00" * byte_len
            for j in S:
                start = j * byte_len
                pad_acc = xor_bytes(pad_acc, pad[start:start + byte_len])
            plain = xor_bytes(enc_vec, pad_acc)
            if plain == fp:
                spatial_ok[rec_idx] = True

    final_ok = [False] * n
    for rec_idx in active_indices:
        final_ok[rec_idx] = matches[rec_idx] and spatial_ok[rec_idx]
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


def run_fast_preview_verification(
    plan: QueryPlan,
    responses: List[dict],
    aui: dict,
    keys: tuple,
    *,
    candidate_positions: List[int] | None,
    sentinel_positions: List[int] | None,
) -> tuple[bool, List]:
    lam = int(aui["security_param"])
    candidate_positions = list(candidate_positions or [])
    sentinel_positions = list(sentinel_positions or [])
    expected_candidate_tag = fast_subset_tag(aui, keys, candidate_positions)
    expected_sentinel_tag = fast_subset_tag(aui, keys, sentinel_positions)

    for resp in responses:
        lhs_candidates = [int(x) for x in resp.get("candidate_positions", [])]
        if lhs_candidates != candidate_positions:
            return False, []
        rhs_sentinels = [int(x) for x in resp.get("sentinel_positions", [])]
        if rhs_sentinels != sentinel_positions:
            return False, []

        candidate_tag_blob = resp.get("candidate_fast_tag")
        if candidate_tag_blob is None:
            return False, []
        if _decode_b64(candidate_tag_blob) != expected_candidate_tag:
            return False, []

        if sentinel_positions:
            sentinel_tag_blob = resp.get("sentinel_fast_tag")
            if sentinel_tag_blob is None:
                return False, []
            if _decode_b64(sentinel_tag_blob) != expected_sentinel_tag:
                return False, []

    if not sentinel_positions:
        return True, []

    combined_sentinel_vecs = combine_sparse_token_vectors(
        plan,
        responses,
        aui,
        result_field="sentinel_result_shares",
        positions_field="sentinel_positions",
    )
    _, sentinel_hits = decrypt_matches(
        plan,
        combined_sentinel_vecs,
        aui,
        keys,
        candidate_positions=sentinel_positions,
    )
    return len(sentinel_hits) == 0, sentinel_hits
