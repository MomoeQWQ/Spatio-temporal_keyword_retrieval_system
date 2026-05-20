"""Shared runtime helpers for online demo scripts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Iterable, List

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))


def http_post(url: str, obj: dict) -> dict:
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            return json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            parsed = json.loads(body)
            msg = parsed.get("error", body)
        except Exception:
            msg = body or str(e)
        raise RuntimeError(f"POST {url} failed ({e.code}): {msg}") from e


def login_and_get_token(csp_base: str, username: str, password: str, ttl_seconds: int = 3600) -> str:
    resp = http_post(
        csp_base + "/auth/login",
        {"username": username, "password": password, "ttl_seconds": ttl_seconds},
    )
    token = str(resp.get("auth_token", "")).strip()
    if not token:
        raise RuntimeError("login succeeded but no auth_token was returned")
    return token


def start_csp_servers(
    ports: Iterable[int],
    *,
    aui_path: str,
    user_db_path: str,
    csp_script_path: str | None = None,
) -> List[subprocess.Popen]:
    script_path = csp_script_path or os.path.join(THIS_DIR, "csp_server.py")
    procs: List[subprocess.Popen] = []
    for p in ports:
        procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    script_path,
                    "--port",
                    str(p),
                    "--aui",
                    aui_path,
                    "--user-db",
                    user_db_path,
                ]
            )
        )
    return procs


def stop_processes(procs: Iterable[subprocess.Popen]) -> None:
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
