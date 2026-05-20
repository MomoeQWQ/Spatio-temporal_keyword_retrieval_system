# DMPF.py (bit-selection shares)

import hashlib


def Gen(security_param, indices, domain_size, num_parties=3):
    """
    Generate U-party bit-selection shares for a set of indices.
    Each party l holds a key s.t. XOR_l Eval(key_l, j) == 1_{j in indices}.
    """
    idx_set = set(int(i) for i in indices)
    base = ",".join(str(i) for i in sorted(idx_set))
    # Precompute shares per j in [0..domain_size-1]
    # For l in 0..U-2: r_l(j) = PRF(l, j); for l=U-1: r = desired XOR XOR_{<U-1} r_l(j)
    shares = [dict() for _ in range(num_parties)]
    for j in range(int(domain_size)):
        desired = 1 if j in idx_set else 0
        xor_prev = 0
        for l in range(num_parties - 1):
            h = hashlib.sha256(f"{base}|{l}|{security_param}|{j}".encode('utf-8')).digest()
            bit = h[0] & 1
            shares[l][j] = bit
            xor_prev ^= bit
        shares[num_parties - 1][j] = desired ^ xor_prev
    # Pack keys
    keys = []
    for l in range(num_parties):
        s = f"{base}|{l}|{security_param}"
        seed = hashlib.sha256(s.encode('utf-8')).hexdigest()
        keys.append({'seed': seed, 'bits': shares[l]})
    return tuple(keys)


def Eval(key, j):
    return key['bits'].get(int(j), 0)
