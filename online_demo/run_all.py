import argparse
import os
import subprocess
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="*", help="query text; leave empty to use client interactive input")
    ap.add_argument("--username", type=str, default="alice")
    ap.add_argument("--password", type=str, default="alice123")
    ap.add_argument("--user-db", type=str, default=None)
    args = ap.parse_args()

    # Start 3 CSP servers
    ports = [8001, 8002, 8003]
    procs = []
    try:
        this_dir = os.path.dirname(os.path.abspath(__file__))
        csp_path = os.path.join(this_dir, 'csp_server.py')
        aui_path = os.path.join(this_dir, 'aui.pkl')
        user_db_path = args.user_db or os.path.join(this_dir, 'users_db.json')
        for p in ports:
            procs.append(
                subprocess.Popen(
                    [sys.executable, csp_path, "--port", str(p), "--aui", aui_path, "--user-db", user_db_path]
                )
            )
        time.sleep(1.5)
        # Run client
        client_path = os.path.join(this_dir, 'client.py')
        query = " ".join(args.query) if args.query else None
        base_cmd = [sys.executable, client_path, "--username", args.username, "--password", args.password]
        if query:
            subprocess.run(base_cmd + ["--query", query])
        else:
            subprocess.run(base_cmd)
    finally:
        for p in procs:
            p.terminate()


if __name__ == '__main__':
    main()
