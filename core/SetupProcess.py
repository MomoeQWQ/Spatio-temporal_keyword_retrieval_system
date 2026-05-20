import os
import math
import hashlib
import hmac


def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def F(key: bytes, data: bytes, output_len: int) -> bytes:
    out = hmac.new(key, data, hashlib.sha256).digest()
    if len(out) >= output_len:
        return out[:output_len]
    full = b""
    counter = 0
    while len(full) < output_len:
        full += hmac.new(key, data + counter.to_bytes(4, 'big'), hashlib.sha256).digest()
        counter += 1
    return full[:output_len]


def FC_eval(key: bytes, data: bytes, output_len: int = 16) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()[:output_len]


def FC_cons(key: bytes, prefix: bytes, output_len: int = 16) -> bytes:
    return hmac.new(key, prefix, hashlib.sha256).digest()[:output_len]


def FX(key: bytes, data: bytes, output_len: int) -> bytes:
    """
    XOR-homomorphic PRF over input bits.
    FX(K, u) = XOR_{bit index b where u_b = 1} PRF(K, b)
    """
    res = b"\x00" * output_len
    bit_index = 0
    for byte in data:
        for k in range(8):
            if (byte >> k) & 1:
                blk = hmac.new(key, b"FX" + bit_index.to_bytes(4, 'big'), hashlib.sha256).digest()[:output_len]
                res = bytes_xor(res, blk)
            bit_index += 1
    return res


def Setup(DB: list, config: dict):
    """
    构造认证索引与密钥，返回 (AUI, (Ke, Kv, Kh)).
    约定：DB 中每个元素拥有属性 id、spatial_gbf.array、keyword_gbf.array。
    """
    n = len(DB)
    lam = config.get("lambda", 16)
    m1 = config["spatial_bloom_filter"]["size"]
    m2 = config["keyword_bloom_filter"]["size"]
    psi = config["keyword_bloom_filter"]["psi"]
    chunk_len = psi // 8

    # Keys
    Ke = os.urandom(lam)
    Kh = os.urandom(lam)
    K_main = os.urandom(lam)
    K_fast = os.urandom(lam)

    # Encrypt GBFs per record -> Ispa, Itex
    Ispa = []
    Itex = []
    raw_spa = []
    raw_tex = []
    for idx, obj in enumerate(DB, start=1):
        bp_i = obj.spatial_gbf.array
        bW_i = obj.keyword_gbf.array
        raw_spa.append(bp_i)
        raw_tex.append(bW_i)
        total_len = (m1 + m2) * chunk_len
        padi = F(Ke, (str(idx) + str(obj.id)).encode('utf-8'), total_len)
        Ebp_i = []
        for j in range(m1):
            start = j * chunk_len
            end = (j + 1) * chunk_len
            Ebp_i.append(bytes_xor(bp_i[j], padi[start:end]))
        EbW_i = []
        for j in range(m2):
            start = (j + m1) * chunk_len
            end = (j + m1 + 1) * chunk_len
            EbW_i.append(bytes_xor(bW_i[j], padi[start:end]))
        Ispa.append(Ebp_i)
        Itex.append(EbW_i)

    # Constrained key for per-record keys
    s_val = config["s"]
    prefix_length = max(0, s_val - math.ceil(math.log2(max(1, n))))
    prefix_bytes = (prefix_length + 7) // 8
    v = os.urandom(prefix_bytes)
    Kv = FC_cons(K_main, v, output_len=lam)

    K_list = []
    for i in range(1, n + 1):
        data_i = str(i).encode('utf-8')
        Ki = FC_eval(Kv, data_i, output_len=lam)
        K_list.append(Ki)

    # Aggregate tags sigma
    cat_ids = "".join([str(obj.id) for obj in DB]).encode('utf-8')
    sigma_spa = []
    for j in range(m1):
        xor_val = b"\x00" * lam
        for i in range(n):
            fx_val = FX(K_list[i], raw_spa[i][j], output_len=lam)
            xor_val = bytes_xor(xor_val, fx_val)
        hmac_val = hmac.new(Kh, str(j + 1).encode('utf-8') + cat_ids, hashlib.sha256).digest()[:lam]
        sigma_spa.append(bytes_xor(xor_val, hmac_val))

    sigma_tex = []
    for j in range(m2):
        xor_val = b"\x00" * lam
        for i in range(n):
            fx_val = FX(K_list[i], raw_tex[i][j], output_len=lam)
            xor_val = bytes_xor(xor_val, fx_val)
        hmac_val = hmac.new(Kh, str(j + 1 + m1).encode('utf-8') + cat_ids, hashlib.sha256).digest()[:lam]
        sigma_tex.append(bytes_xor(xor_val, hmac_val))

    Ispa_tilde = {"Ebp": Ispa, "sigma": sigma_spa}
    Itex_tilde = {"EbW": Itex, "sigma": sigma_tex}

    authenticated_index = {
        "I_tex": Itex_tilde,
        "I_spa": Ispa_tilde,
        "m_prime_1": config.get("m_prime_1"),
        "m_prime_2": config.get("m_prime_2"),
        "m1": m1,
        "m2": m2,
        "security_param": lam,
        "U": config.get("U"),
        "segment_length": chunk_len,
        "ids": [obj.id for obj in DB],
        "k_spa": config.get("spatial_bloom_filter", {}).get("hash_count", 3),
        "k_tex": config.get("keyword_bloom_filter", {}).get("hash_count", 4),
        "cuckoo_kw": {
            "kappa": config.get('cuckoo', {}).get('kappa_kw', 3),
            "load": config.get('cuckoo', {}).get('load_kw', 1.27),
            "seed": config.get('cuckoo', {}).get('seed_kw', 'cuckoo-seed'),
        },
        "cuckoo_spa": {
            "kappa": config.get('cuckoo', {}).get('kappa_spa', 3),
            "load": config.get('cuckoo', {}).get('load_spa', 1.27),
            "seed": config.get('cuckoo', {}).get('seed_spa', 'cuckoo-seed-spa'),
        },
        "fast_tags": {
            "rows": [
                hmac.new(
                    K_fast,
                    b"row|" + str(idx).encode('utf-8') + b"|" + str(obj.id).encode('utf-8'),
                    hashlib.sha256,
                ).digest()[:lam]
                for idx, obj in enumerate(DB, start=1)
            ],
        },
    }

    K_final = (Ke, Kv, Kh, K_fast)
    return authenticated_index, K_final
