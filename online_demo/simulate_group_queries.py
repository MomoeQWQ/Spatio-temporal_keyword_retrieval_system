"""Local simulation for group-based search communication and permissions."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from online_demo.runtime_utils import (
    http_post,
    login_and_get_token,
    start_csp_servers,
    stop_processes,
)


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
    procs: list[subprocess.Popen] = []
    try:
        procs = start_csp_servers(ports, aui_path=args.aui, user_db_path=args.user_db)
        time.sleep(1.8)

        # Use admin account to create a new privileged group and user online.
        admin_token = login_and_get_token(csp_urls[0], "admin", "admin123")
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
        stop_processes(procs)


if __name__ == "__main__":
    main()
