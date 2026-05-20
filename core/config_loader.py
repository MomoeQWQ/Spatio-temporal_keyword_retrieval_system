import configparser


def load_config(path: str) -> dict:
    """
    Load configuration from an INI file, providing sane defaults.
    Expects sections: general, spatial_bloom_filter, keyword_bloom_filter, suppression (optional).
    """
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")

    # Defaults
    general = {
        "lambda": 16,
        "s": 64,
        "m_prime_1": 200,
        "m_prime_2": 200,
        "U": 3,
    }
    if parser.has_section("general"):
        sec = parser["general"]
        general.update({
            "lambda": sec.getint("lambda", general["lambda"]),
            "s": sec.getint("s", general["s"]),
            "m_prime_1": sec.getint("m_prime_1", general["m_prime_1"]),
            "m_prime_2": sec.getint("m_prime_2", general["m_prime_2"]),
            "U": sec.getint("U", general["U"]),
        })

    spatial = {
        "size": 200,
        "hash_count": 3,
        "psi": 32,
    }
    if parser.has_section("spatial_bloom_filter"):
        sec = parser["spatial_bloom_filter"]
        spatial.update({
            "size": sec.getint("size", spatial["size"]),
            "hash_count": sec.getint("hash_count", spatial["hash_count"]),
            "psi": sec.getint("psi", spatial["psi"]),
        })

    keyword = {
        "size": 200,
        "hash_count": 4,
        "psi": 32,
    }
    if parser.has_section("keyword_bloom_filter"):
        sec = parser["keyword_bloom_filter"]
        keyword.update({
            "size": sec.getint("size", keyword["size"]),
            "hash_count": sec.getint("hash_count", keyword["hash_count"]),
            "psi": sec.getint("psi", keyword["psi"]),
        })

    suppression = {
        "enable_padding": True,
        "max_r_blocks": 4,
        "enable_blinding": True,
    }
    if parser.has_section("suppression"):
        sec = parser["suppression"]
        suppression.update({
            "enable_padding": sec.getboolean("enable_padding", suppression["enable_padding"]),
            "max_r_blocks": sec.getint("max_r_blocks", suppression["max_r_blocks"]),
            "enable_blinding": sec.getboolean("enable_blinding", suppression["enable_blinding"]),
        })

    cuckoo = {
        "kappa_kw": 3,
        "load_kw": 1.27,
        "seed_kw": "cuckoo-seed",
        "kappa_spa": 3,
        "load_spa": 1.27,
        "seed_spa": "cuckoo-seed-spa",
    }
    if parser.has_section("cuckoo"):
        sec = parser["cuckoo"]
        cuckoo.update({
            "kappa_kw": sec.getint("kappa_kw", cuckoo["kappa_kw"]),
            "load_kw": sec.getfloat("load_kw", cuckoo["load_kw"]),
            "seed_kw": sec.get("seed_kw", cuckoo["seed_kw"]),
            "kappa_spa": sec.getint("kappa_spa", cuckoo["kappa_spa"]),
            "load_spa": sec.getfloat("load_spa", cuckoo["load_spa"]),
            "seed_spa": sec.get("seed_spa", cuckoo["seed_spa"]),
        })

    return {
        **general,
        "spatial_bloom_filter": spatial,
        "keyword_bloom_filter": keyword,
        "suppression": suppression,
        "spatial_grid": {
            "cell_size_lat": float(parser.get("spatial_grid", "cell_size_lat", fallback="0.5")) if parser.has_section("spatial_grid") else 0.5,
            "cell_size_lon": float(parser.get("spatial_grid", "cell_size_lon", fallback="0.5")) if parser.has_section("spatial_grid") else 0.5,
        },
        "cuckoo": cuckoo,
    }
