import hashlib
from math import ceil
from core.QueryUtils import pad_query_blocks, tokenize_normalized
from core import DMPF


def _hash_positions(item: str, size: int, hash_count: int) -> list:
    h1 = int(hashlib.sha256(item.encode('utf-8')).hexdigest(), 16)
    h2 = int(hashlib.md5(item.encode('utf-8')).hexdigest(), 16)
    return [(h1 + i * h2) % size for i in range(hash_count)]


def _prp(zeta: bytes, x: int) -> int:
    """Pseudo-random permutation output (integer) using SHA-256 keyed with seed zeta."""
    return int(hashlib.sha256(zeta + x.to_bytes(8, 'big')).hexdigest(), 16)


def _cuckoo_bucketize(indices: list, m: int, kappa: int, M: int, zeta: bytes) -> dict:
    """
    PRP-based Cuckoo bucketing: for each index j in indices, compute kappa candidate buckets
    and place j into the currently lightest bucket among its candidates. Returns {bucket_id: [col_idx,...]}.
    """
    buckets = {b: [] for b in range(M)}
    for j in indices:
        cands = []
        for i in range(kappa):
            val = _prp(zeta, j + m * i)
            b = val % M
            cands.append(b)
        # choose lightest bucket among candidates
        best = min(cands, key=lambda b: len(buckets[b]))
        buckets[best].append(j)
    # remove empty buckets
    return {b: lst for b, lst in buckets.items() if lst}


def search_process(query, authenticated_index, suppression=None, spa_cells: list | None = None):
    """
    浠呭熀浜庡叧閿瘝 GBF 鐨勬寜瀛楄妭 XOR 鑱氬悎锛?
      - 姣忎釜鏌ヨ璇嶇敓鎴愬垪閫夋嫨闆嗗悎锛圙BF 鍝堝笇浣嶇疆锛?
      - DMPF 杩斿洖鍚勬柟鍦ㄦ瘡鍒楃殑姣旂壒浠介锛圶OR 鍚庡緱鍒伴€夋嫨浣嶏級
      - 鍚勬柟璁＄畻瀵硅薄绾у悜閲忎唤棰濓細瀵硅閫夋嫨鐨勫垪閫愬垪鎸夊瓧鑺?XOR
      - 璇佹槑浠介锛氬搴?sigma 鍒楁寜瀛楄妭 XOR
    杩斿洖: (result_shares, proof_shares)
    """
    I_tex = authenticated_index['I_tex']
    m2 = authenticated_index['m2']
    U = authenticated_index['U']
    security_param = authenticated_index['security_param']
    k_tex = authenticated_index.get('k_tex', 4)

    toks = tokenize_normalized(query)
    tokens = toks or [query]
    # 鍙€夛細鍥哄畾 R 鍧楁暟閲忥紙姝ゅ鍙娇鐢ㄥ叧閿瘝鍧楋紝padding 涓嶅奖鍝嶉€昏緫锛?
    if suppression and suppression.get('enable_padding', True):
        max_r = suppression.get('max_r_blocks', 4)
        if len(tokens) > max_r:
            tokens = tokens[:max_r]

    n = len(I_tex["EbW"])  # 瀵硅薄鏁?
    byte_len = len(I_tex["EbW"][0][0]) if n and I_tex["EbW"][0] else 0

    result_shares = {l: [] for l in range(U)}
    proof_shares = {l: [] for l in range(U)}

    # 鍏抽敭璇?token 璺緞
    for tok in tokens:
        indices = _hash_positions(tok, m2, k_tex)
        # PRP-based Cuckoo hashing parameters
        ck = authenticated_index.get('cuckoo_kw', {"kappa": 3, "load": 1.27, "seed": "cuckoo-seed"})
        kappa = min(int(ck.get('kappa', 3)), k_tex)
        M = max(1, int(ceil(float(ck.get('load', 1.27)) * max(1, len(indices)))))
        zeta = str(ck.get('seed', 'cuckoo-seed')).encode('utf-8')
        buckets = _cuckoo_bucketize(indices, m2, kappa, M, zeta)
        # For each party, aggregate per-bucket results then XOR across buckets
        for l in range(U):
            vec_total = [b"\x00" * byte_len for _ in range(n)]
            proof_total = b"\x00" * security_param
            for b_id, cols in buckets.items():
                domain_size = len(cols)
                # All positions in this bucket are selected
                keys = DMPF.Gen(security_param, list(range(domain_size)), domain_size, num_parties=U)
                # selection bits for this bucket
                sel_bits = [DMPF.Eval(keys[l], j_local) for j_local in range(domain_size)]
                # aggregate columns in this bucket according to sel_bits (will be all ones after combine across parties)
                for local_idx, col_idx in enumerate(cols):
                    if sel_bits[local_idx] == 1:
                        col_cells = [row[col_idx] for row in I_tex["EbW"]]
                        for i in range(n):
                            vec_total[i] = bytes(a ^ b for a, b in zip(vec_total[i], col_cells[i]))
                        proof_total = bytes(a ^ b for a, b in zip(proof_total, I_tex["sigma"][col_idx]))
            result_shares[l].append(vec_total)
            proof_shares[l].append(proof_total)

    # 绌洪棿 token 璺緞锛堝彲閫夛級
    if spa_cells:
        k_spa = authenticated_index.get('k_spa', 3)
        m1 = authenticated_index['m1']
        for cell in spa_cells:
            indices = _hash_positions(cell, m1, k_spa)
            ck = authenticated_index.get('cuckoo_spa', {"kappa": 3, "load": 1.27, "seed": "cuckoo-seed-spa"})
            kappa = min(int(ck.get('kappa', 3)), k_spa)
            M = max(1, int(ceil(float(ck.get('load', 1.27)) * max(1, len(indices)))))
            zeta = str(ck.get('seed', 'cuckoo-seed-spa')).encode('utf-8')
            buckets = _cuckoo_bucketize(indices, m1, kappa, M, zeta)
            for l in range(U):
                vec_total = [b"\x00" * byte_len for _ in range(n)]
                proof_total = b"\x00" * security_param
                for b_id, cols in buckets.items():
                    domain_size = len(cols)
                    keys = DMPF.Gen(security_param, list(range(domain_size)), domain_size, num_parties=U)
                    sel_bits = [DMPF.Eval(keys[l], j_local) for j_local in range(domain_size)]
                    for local_idx, col_idx in enumerate(cols):
                        if sel_bits[local_idx] == 1:
                            col_cells = [row[col_idx] for row in authenticated_index['I_spa']["Ebp"]]
                            for i in range(n):
                                vec_total[i] = bytes(a ^ b for a, b in zip(vec_total[i], col_cells[i]))
                            proof_total = bytes(a ^ b for a, b in zip(proof_total, authenticated_index['I_spa']["sigma"][col_idx]))
                result_shares[l].append(vec_total)
                proof_shares[l].append(proof_total)

    return result_shares, proof_shares

