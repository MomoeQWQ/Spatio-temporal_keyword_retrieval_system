import argparse
import os
import subprocess
import sys
import time

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, '..'))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from online_demo.runtime_utils import start_csp_servers, stop_processes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="*", help="query text; leave empty to use client interactive input")
    ap.add_argument("--username", type=str, default="alice")
    ap.add_argument("--password", type=str, default="alice123")
    ap.add_argument("--user-db", type=str, default=None)
    args = ap.parse_args()

    ports = [8001, 8002, 8003]
    procs = []
    try:
        aui_path = os.path.join(THIS_DIR, 'aui.pkl')
        user_db_path = args.user_db or os.path.join(THIS_DIR, 'users_db.json')
        procs = start_csp_servers(ports, aui_path=aui_path, user_db_path=user_db_path)
        time.sleep(1.5)
        client_path = os.path.join(THIS_DIR, 'client.py')
        query = " ".join(args.query) if args.query else None
        base_cmd = [sys.executable, client_path, "--username", args.username, "--password", args.password]
        if query:
            subprocess.run(base_cmd + ["--query", query])
        else:
            subprocess.run(base_cmd)
    finally:
        stop_processes(procs)


if __name__ == '__main__':
    main()
