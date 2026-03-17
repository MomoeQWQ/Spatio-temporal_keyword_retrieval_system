from __future__ import annotations

import json
import os
from typing import Dict, List

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
CONFIG_PATH = os.path.join(THIS_DIR, "web_config.json")


def default_config() -> Dict:
    return {
        "web_host": "127.0.0.1",
        "web_port": 5099,
        "aui_path": os.path.join(PROJ_ROOT, "online_demo", "aui.pkl"),
        "keys_path": os.path.join(PROJ_ROOT, "online_demo", "K.pkl"),
        "config_path": os.path.join(PROJ_ROOT, "conFig.ini"),
        "dataset_path": os.path.join(PROJ_ROOT, "us-colleges-and-universities.csv"),
        "user_db_path": os.path.join(PROJ_ROOT, "online_demo", "users_db.json"),
        "csp_ports": [8001, 8002, 8003],
    }


def load_config() -> Dict:
    cfg = default_config()
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        cfg.update(raw)
    cfg["csp_ports"] = _normalize_ports(cfg.get("csp_ports", []))
    return cfg


def save_config(cfg: Dict) -> None:
    current = default_config()
    current.update(cfg)
    current["csp_ports"] = _normalize_ports(current.get("csp_ports", []))
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(current, f, ensure_ascii=False, indent=2)


def ports_to_csv(ports: List[int]) -> str:
    return ",".join(str(int(p)) for p in _normalize_ports(ports))


def parse_ports_csv(text: str) -> List[int]:
    items = [x.strip() for x in str(text).split(",") if x.strip()]
    return _normalize_ports([int(x) for x in items])


def csp_endpoints(cfg: Dict) -> List[str]:
    return [f"http://127.0.0.1:{p}" for p in _normalize_ports(cfg.get("csp_ports", []))]


def _normalize_ports(ports_like) -> List[int]:
    out: List[int] = []
    for p in ports_like:
        try:
            pi = int(p)
        except Exception:
            continue
        if 1 <= pi <= 65535:
            out.append(pi)
    dedup = sorted(set(out))
    return dedup
