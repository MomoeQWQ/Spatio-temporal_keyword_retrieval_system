import hashlib
import hmac
from core.SetupProcess import FC_eval, FX, F
from core.QueryUtils import tokenize_normalized


def _split_keys(key_tuple: tuple) -> tuple[bytes, bytes, bytes, bytes | None]:
    if len(key_tuple) >= 4:
        return key_tuple[0], key_tuple[1], key_tuple[2], key_tuple[3]
    return key_tuple[0], key_tuple[1], key_tuple[2], None


def _col_bytes(matrix_2d):
    """
    Convert a 2D list of bytes (rows x cols) into a list of column-wise concatenated bytes.
    """
    if not matrix_2d:
        return []
    rows = len(matrix_2d)
    cols = len(matrix_2d[0])
    cols_bytes = []
    for j in range(cols):
        b = b"".join(matrix_2d[i][j] for i in range(rows))
        cols_bytes.append(b)
    return cols_bytes


def build_integrity_tags(authenticated_index: dict, K_final: tuple) -> dict:
    """
    Build HMAC-based integrity tags for the encrypted index columns.
    Does not change the authenticated_index; returns a separate tag structure.

    Tags: tau_spa[j] = HMAC(Kh, b"spa|j|" || concat_col_j)
          tau_tex[j] = HMAC(Kh, b"tex|j|" || concat_col_j)
    """
    _, _, Kh, _ = _split_keys(K_final)
    I_spa = authenticated_index["I_spa"]["Ebp"]
    I_tex = authenticated_index["I_tex"]["EbW"]

    spa_cols = _col_bytes(I_spa)
    tex_cols = _col_bytes(I_tex)

    tau_spa = []
    for j, col in enumerate(spa_cols, start=1):
        tag = hmac.new(Kh, (b"spa|" + str(j).encode("utf-8") + b"|") + col, hashlib.sha256).digest()
        tau_spa.append(tag)

    tau_tex = []
    for j, col in enumerate(tex_cols, start=1):
        tag = hmac.new(Kh, (b"tex|" + str(j).encode("utf-8") + b"|") + col, hashlib.sha256).digest()
        tau_tex.append(tag)

    return {"tau_spa": tau_spa, "tau_tex": tau_tex}


def verify_integrity(authenticated_index: dict, K_final: tuple, tags: dict) -> bool:
    """
    Verify integrity tags against the current authenticated index.
    Returns True if all tags match.
    """
    expected = build_integrity_tags(authenticated_index, K_final)
    if len(expected["tau_spa"]) != len(tags.get("tau_spa", [])):
        return False
    if len(expected["tau_tex"]) != len(tags.get("tau_tex", [])):
        return False
    for a, b in zip(expected["tau_spa"], tags["tau_spa"]):
        if a != b:
            return False
    for a, b in zip(expected["tau_tex"], tags["tau_tex"]):
        if a != b:
            return False
    return True


def fast_subset_tag(authenticated_index: dict, K_final: tuple, positions: list[int] | None) -> bytes:
    _, _, _, K_fast = _split_keys(K_final)
    lam = int(authenticated_index.get("security_param", 16))
    positions = [int(x) for x in (positions or [])]
    if not positions:
        return b"\x00" * lam

    row_tags = authenticated_index.get("fast_tags", {}).get("rows")
    if row_tags:
        tag = b"\x00" * lam
        for idx in positions:
            if 0 <= idx < len(row_tags):
                tag = bytes(a ^ b for a, b in zip(tag, row_tags[idx]))
        return tag

    if K_fast is None:
        raise ValueError("fast preview verification requires K_fast or precomputed fast_tags")

    ids = authenticated_index.get("ids", [])
    tag = b"\x00" * lam
    for idx in positions:
        if 0 <= idx < len(ids):
            row_tag = hmac.new(
                K_fast,
                b"row|" + str(idx + 1).encode("utf-8") + b"|" + str(ids[idx]).encode("utf-8"),
                hashlib.sha256,
            ).digest()[:lam]
            tag = bytes(a ^ b for a, b in zip(tag, row_tag))
    return tag


def verify_fx_hmac(query: str, authenticated_index: dict, K_final: tuple,
                   combined_vectors: list, combined_proofs: list,
                   tokens_override: list | None = None) -> bool:
    """
    Strict verification per paper: For each token block t,
      combined_proof[t] == (XOR_i FX(Ki, res_t[i])) XOR N_S,ID
    where Ki = FC_eval(Kv, i), N_S,ID = XOR_{j in S} HMAC(Kh, (j+m1)||cat_ids)

    - combined_vectors: list of object-level plaintext XOR vectors per token (bytes per object)
      Caller must pass decrypted res_t[i] (after removing one-time pad on selected columns).
    - combined_proofs: list of bytes (XOR of sigma over selected columns)
    """
    Ke, Kv, Kh, _ = _split_keys(K_final)
    ids = authenticated_index.get('ids', [])
    m1 = authenticated_index['m1']
    m2 = authenticated_index['m2']
    lam = authenticated_index['security_param']
    byte_len = authenticated_index['segment_length']
    k_tex = authenticated_index.get('k_tex', 4)
    k_spa = authenticated_index.get('k_spa', 3)

    cat_ids = "".join(str(x) for x in ids).encode('utf-8')

    # Selection indices per normalized token
    import hashlib
    def _hash_pos(item: str, size: int, k: int):
        h1 = int(hashlib.sha256(item.encode('utf-8')).hexdigest(), 16)
        h2 = int(hashlib.md5(item.encode('utf-8')).hexdigest(), 16)
        return [(h1 + i * h2) % size for i in range(k)]

    tokens = tokens_override if tokens_override is not None else (tokenize_normalized(query) or [query])

    if len(tokens) != len(combined_vectors) or len(tokens) != len(combined_proofs):
        return False

    n = len(ids)
    for t_idx, tok in enumerate(tokens):
        is_spatial = isinstance(tok, str) and tok.startswith("CELL:")
        if is_spatial:
            indices = _hash_pos(tok, m1, k_spa)
        else:
            indices = _hash_pos(tok, m2, k_tex)
        # sum FX over objects
        fx_sum = b"\x00" * lam
        fx_pad_sum = b"\x00" * lam
        for i in range(1, n + 1):
            Ki = FC_eval(Kv, str(i).encode('utf-8'), output_len=lam)
            fx_val = FX(Ki, combined_vectors[t_idx][i - 1], output_len=lam)
            fx_sum = bytes(a ^ b for a, b in zip(fx_sum, fx_val))
            # pad_acc for this object and token selection
            total_len = (m1 + m2) * byte_len
            pad = F(K_final[0], (str(i) + str(ids[i - 1])).encode('utf-8'), total_len)
            pad_acc = b"\x00" * byte_len
            for j in indices:
                start = (j * byte_len) if is_spatial else ((m1 + j) * byte_len)
                pad_acc = bytes(a ^ b for a, b in zip(pad_acc, pad[start:start + byte_len]))
            fx_pad = FX(Ki, pad_acc, output_len=lam)
            fx_pad_sum = bytes(a ^ b for a, b in zip(fx_pad_sum, fx_pad))
        # N_S,ID
        nsid = b"\x00" * lam
        for j in indices:
            if is_spatial:
                h = hmac.new(Kh, str(j + 1).encode('utf-8') + cat_ids, hashlib.sha256).digest()[:lam]
            else:
                h = hmac.new(Kh, str(j + 1 + m1).encode('utf-8') + cat_ids, hashlib.sha256).digest()[:lam]
            nsid = bytes(a ^ b for a, b in zip(nsid, h))
        expected = bytes(a ^ b for a, b in zip(fx_sum, nsid))
        expected = bytes(a ^ b for a, b in zip(expected, fx_pad_sum))
        if expected != combined_proofs[t_idx]:
            return False
    return True
