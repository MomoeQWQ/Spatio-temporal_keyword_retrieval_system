"""Local simulation for group-based search communication and permissions."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def http_post(url: str, obj: dict) -> dict:
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            parsed = json.loads(body)
            msg = parsed.get("error", body)
        except Exception:
            msg = body or str(e)
        raise RuntimeError(f"POST {url} failed ({e.code}): {msg}") from e


def login(base: str, username: str, password: str) -> str:
    resp = http_post(base + "/auth/login", {"username": username, "password": password, "ttl_seconds": 3600})
    token = str(resp.get("auth_token", "")).strip()
    if not token:
        raise RuntimeError("login returned empty auth_token")
    return token


def run_client(query: str, username: str, password: str, csp_urls: list[str]) -> tuple[int, str]:
    client_path = os.path.join(THIS_DIR, "client.py")
    cmd = [
        sys.executable,
        client_path,
        "--query",
        query,
        "--username",
        username,
        "--password",
        password,
        "--csp",
        *csp_urls,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output.strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--aui", type=str, default=os.path.join(THIS_DIR, "aui.pkl"))
    ap.add_argument("--user-db", type=str, default=os.path.join(THIS_DIR, "users_db.json"))
    ap.add_argument("--spatial-query", type=str, default="ORLANDO; R: 28.3,-81.5,28.7,-81.2")
    ap.add_argument("--keyword-query", type=str, default="ORLANDO")
    args = ap.parse_args()

    ports = [8001, 8002, 8003]
    csp_urls = [f"http://127.0.0.1:{p}" for p in ports]
    csp_script = os.path.join(THIS_DIR, "csp_server.py")
    procs: list[subprocess.Popen] = []
    try:
        for p in ports:
            procs.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        csp_script,
                        "--port",
                        str(p),
                        "--aui",
                        args.aui,
                        "--user-db",
                        args.user_db,
                    ]
                )
            )
        time.sleep(1.8)

        # Use admin account to create a new privileged group and user online.
        admin_token = login(csp_urls[0], "admin", "admin123")
        http_post(
            csp_urls[0] + "/admin/create_group",
            {
                "auth_token": admin_token,
                "group_name": "power_user",
                "policy": {
                    "can_search": True,
                    "allow_spatial": True,
                    "max_keywords": 8,
                    "can_manage_users": False,
                    "can_manage_groups": False,
                },
            },
        )
        http_post(
            csp_urls[0] + "/admin/create_user",
            {
                "auth_token": admin_token,
                "username": "charlie",
                "password": "charlie123",
                "groups": ["power_user"],
                "active": True,
            },
        )

        checks = [
            {
                "name": "analyst spatial allowed",
                "username": "alice",
                "password": "alice123",
                "query": args.spatial_query,
                "should_succeed": True,
                "expect_text": "[client] Verify: pass",
            },
            {
                "name": "guest spatial denied",
                "username": "bob",
                "password": "bob123",
                "query": args.spatial_query,
                "should_succeed": False,
                "expect_text": "not allowed to issue spatial queries",
            },
            {
                "name": "guest keyword allowed",
                "username": "bob",
                "password": "bob123",
                "query": args.keyword_query,
                "should_succeed": True,
                "expect_text": "[client] Verify: pass",
            },
            {
                "name": "new power_user spatial allowed",
                "username": "charlie",
                "password": "charlie123",
                "query": args.spatial_query,
                "should_succeed": True,
                "expect_text": "[client] Verify: pass",
            },
        ]

        failures = []
        for c in checks:
            code, out = run_client(c["query"], c["username"], c["password"], csp_urls)
            succeeded = code == 0
            text_ok = c["expect_text"] in out
            status_ok = succeeded == bool(c["should_succeed"])
            ok = status_ok and text_ok
            print(f"[simulate] {c['name']}: {'PASS' if ok else 'FAIL'}")
            if not ok:
                failures.append(
                    {
                        "name": c["name"],
                        "return_code": code,
                        "expected_success": c["should_succeed"],
                        "expected_text": c["expect_text"],
                        "output_tail": "\n".join(out.splitlines()[-12:]),
                    }
                )

        if failures:
            print("[simulate] Failures detail:")
            for f in failures:
                print(json.dumps(f, ensure_ascii=False, indent=2))
            raise SystemExit(1)

        print("[simulate] All group-based communication checks passed.")
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    main()
