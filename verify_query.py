from QueryUtils import pad_query_blocks
import hashlib


def _hash_pos(item: str, size: int, k: int):
    h1 = int(hashlib.sha256(item.encode('utf-8')).hexdigest(), 16)
    h2 = int(hashlib.md5(item.encode('utf-8')).hexdigest(), 16)
    return [(h1 + i * h2) % size for i in range(k)]


def recompute_proofs_only(query: str, AUI: dict, suppression: dict | None):
    I_tex = AUI['I_tex']
    m2 = AUI['m2']
    k_tex = AUI.get('k_tex', 4)

    tokens = [t for t in query.split() if t.strip()] or [query]
    if suppression and suppression.get('enable_padding', True):
        max_r = suppression.get('max_r_blocks', 4)
        if len(tokens) > max_r:
            tokens = tokens[:max_r]

    proofs = []
    lam = len(I_tex['sigma'][0]) if I_tex['sigma'] else 16
    for tok in tokens:
        idxs = _hash_pos(tok, m2, k_tex)
        p = b"\x00" * lam
        for j in idxs:
            p = bytes(a ^ b for a, b in zip(p, I_tex['sigma'][j]))
        proofs.append(p)
    return proofs


def verify_demo(query: str, AUI: dict, result_shares: dict, proof_shares: dict, suppression: dict | None) -> bool:
    parties = sorted(proof_shares.keys())
    if not parties:
        return False
    num_blocks = len(proof_shares[parties[0]])
    combined_proofs = []
    for i in range(num_blocks):
        p = b"\x00" * len(proof_shares[parties[0]][i])
        for l in parties:
            p = bytes(a ^ b for a, b in zip(p, proof_shares[l][i]))
        combined_proofs.append(p)
    expected = recompute_proofs_only(query, AUI, suppression)
    return combined_proofs == expected

