import argparse
import base64
import json
import os
import sys
import pickle
from http.server import BaseHTTPRequestHandler, HTTPServer

# Ensure project root in path
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJ_ROOT = os.path.abspath(os.path.join(THIS_DIR, '..', '..'))
if PROJ_ROOT not in sys.path:
    sys.path.insert(0, PROJ_ROOT)

from core.secure_search.native_accel import NATIVE_ACCEL_ENABLED, xor_bytes, xor_pair_lists
from apps.cli.user_management import (
    authenticate_user,
    assign_groups,
    authorize_query,
    create_or_update_group,
    create_or_update_user,
    ensure_user_db,
    list_users_public,
    load_user_db,
    save_user_db,
    verify_token,
)


class CSPState:
    aui = None
    user_db_path = os.path.join(THIS_DIR, "users_db.json")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code=200, obj=None):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        if obj is not None:
            self.wfile.write(json.dumps(obj).encode('utf-8'))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        data = self.rfile.read(length)
        try:
            payload = json.loads(data.decode('utf-8'))
        except Exception as e:
            return self._send(400, {"error": f"invalid json: {e}"})

        if self.path == '/load_index':
            # Accept base64 pickle or file path
            try:
                if 'aui_b64' in payload:
                    aui = pickle.loads(base64.b64decode(payload['aui_b64']))
                elif 'aui_path' in payload:
                    with open(payload['aui_path'], 'rb') as f:
                        aui = pickle.load(f)
                else:
                    return self._send(400, {"error": "aui_b64 or aui_path required"})
                CSPState.aui = aui
                return self._send(200, {"status": "ok"})
            except Exception as e:
                return self._send(500, {"error": f"load_index failed: {e}"})

        if self.path == '/auth/login':
            try:
                username = str(payload.get('username', '')).strip()
                password = str(payload.get('password', ''))
                ttl_seconds = int(payload.get('ttl_seconds', 3600))
                if not username or not password:
                    return self._send(400, {"error": "username and password are required"})
                db = load_user_db(CSPState.user_db_path)
                result, err = authenticate_user(db, username, password, ttl_seconds=ttl_seconds)
                if err:
                    return self._send(401, {"error": err})
                return self._send(200, result)
            except Exception as e:
                return self._send(500, {"error": f"login failed: {e}"})

        if self.path == '/auth/whoami':
            try:
                token = str(payload.get('auth_token', '')).strip()
                if not token:
                    return self._send(401, {"error": "auth_token required"})
                db = load_user_db(CSPState.user_db_path)
                profile, err = verify_token(db, token)
                if err:
                    return self._send(401, {"error": err})
                return self._send(200, {"user": profile})
            except Exception as e:
                return self._send(500, {"error": f"whoami failed: {e}"})

        if self.path.startswith('/admin/'):
            try:
                token = str(payload.get('auth_token', '')).strip()
                if not token:
                    return self._send(401, {"error": "auth_token required"})
                db = load_user_db(CSPState.user_db_path)
                profile, err = verify_token(db, token)
                if err:
                    return self._send(401, {"error": err})

                perms = profile.get('permissions', {})
                if self.path in ('/admin/create_user', '/admin/assign_groups', '/admin/list_users'):
                    if not bool(perms.get('can_manage_users', False)):
                        return self._send(403, {"error": "permission denied: can_manage_users required"})
                if self.path in ('/admin/create_group', '/admin/list_groups'):
                    if not bool(perms.get('can_manage_groups', False)):
                        return self._send(403, {"error": "permission denied: can_manage_groups required"})

                if self.path == '/admin/create_group':
                    group_name = str(payload.get('group_name', '')).strip()
                    policy = payload.get('policy', {})
                    if not group_name:
                        return self._send(400, {"error": "group_name is required"})
                    if not isinstance(policy, dict):
                        return self._send(400, {"error": "policy must be an object"})
                    create_or_update_group(db, group_name, policy)
                    save_user_db(db, CSPState.user_db_path)
                    return self._send(200, {"status": "ok", "group_name": group_name, "policy": db['groups'][group_name]})

                if self.path == '/admin/create_user':
                    username = str(payload.get('username', '')).strip()
                    password = payload.get('password', None)
                    groups = payload.get('groups', [])
                    active = bool(payload.get('active', True))
                    if not username:
                        return self._send(400, {"error": "username is required"})
                    if not isinstance(groups, list):
                        return self._send(400, {"error": "groups must be a list"})
                    unknown_groups = [g for g in groups if g not in db.get('groups', {})]
                    if unknown_groups:
                        return self._send(400, {"error": f"unknown groups: {unknown_groups}"})
                    create_or_update_user(db, username, password, groups=groups, active=active)
                    save_user_db(db, CSPState.user_db_path)
                    return self._send(200, {"status": "ok", "user": username})

                if self.path == '/admin/assign_groups':
                    username = str(payload.get('username', '')).strip()
                    groups = payload.get('groups', [])
                    if not username:
                        return self._send(400, {"error": "username is required"})
                    if not isinstance(groups, list):
                        return self._send(400, {"error": "groups must be a list"})
                    unknown_groups = [g for g in groups if g not in db.get('groups', {})]
                    if unknown_groups:
                        return self._send(400, {"error": f"unknown groups: {unknown_groups}"})
                    ok, msg = assign_groups(db, username, groups)
                    if not ok:
                        return self._send(404, {"error": msg})
                    save_user_db(db, CSPState.user_db_path)
                    return self._send(200, {"status": "ok", "user": username, "groups": groups})

                if self.path == '/admin/list_users':
                    return self._send(200, {"users": list_users_public(db)})

                if self.path == '/admin/list_groups':
                    return self._send(200, {"groups": db.get('groups', {})})

                return self._send(404, {"error": "admin endpoint not found"})
            except Exception as e:
                return self._send(500, {"error": f"admin failed: {e}"})

        if self.path == '/eval':
            try:
                aui = CSPState.aui
                if aui is None:
                    return self._send(400, {"error": "AUI not loaded"})
                db = load_user_db(CSPState.user_db_path)
                token = str(payload.get('auth_token', '')).strip()
                if not token:
                    return self._send(401, {"error": "auth_token required"})
                profile, err = verify_token(db, token)
                if err:
                    return self._send(401, {"error": err})
                party_id = int(payload.get('party_id', 0))
                tokens = payload.get('tokens', [])
                ok, reason = authorize_query(profile, tokens)
                if not ok:
                    return self._send(403, {"error": reason})
                lam = int(payload.get('security_param', aui['security_param']))
                n = len(aui['ids'])
                byte_len = aui['segment_length']
                fast_row_tags = aui.get('fast_tags', {}).get('rows', [])
                candidate_positions = payload.get('candidate_positions')
                if candidate_positions is None:
                    candidate_positions_norm = None
                else:
                    if not isinstance(candidate_positions, list):
                        return self._send(400, {"error": "candidate_positions must be a list"})
                    candidate_positions_norm = []
                    seen = set()
                    for x in candidate_positions:
                        idx = int(x)
                        if 0 <= idx < n and idx not in seen:
                            candidate_positions_norm.append(idx)
                            seen.add(idx)
                sentinel_positions = payload.get('sentinel_positions')
                if sentinel_positions is None:
                    sentinel_positions_norm = None
                else:
                    if not isinstance(sentinel_positions, list):
                        return self._send(400, {"error": "sentinel_positions must be a list"})
                    sentinel_positions_norm = []
                    seen = set()
                    for x in sentinel_positions:
                        idx = int(x)
                        if 0 <= idx < n and idx not in seen:
                            sentinel_positions_norm.append(idx)
                            seen.add(idx)

                def _fast_subset_tag(positions):
                    if not positions:
                        return b"\x00" * lam
                    tag = b"\x00" * lam
                    for idx in positions:
                        if 0 <= idx < len(fast_row_tags):
                            tag = xor_bytes(tag, fast_row_tags[idx])
                    return tag

                result_shares = []
                proof_shares = []
                sentinel_result_shares = []
                for tok in tokens:
                    typ = tok.get('type', 'kw')
                    buckets = tok.get('buckets', [])
                    if candidate_positions_norm is None:
                        vec_total = [b"\x00" * byte_len for _ in range(n)]
                    else:
                        vec_total = [b"\x00" * byte_len for _ in range(len(candidate_positions_norm))]
                    if sentinel_positions_norm is not None:
                        sentinel_vec_total = [b"\x00" * byte_len for _ in range(len(sentinel_positions_norm))]
                    else:
                        sentinel_vec_total = None
                    proof_total = b"\x00" * lam
                    if typ == 'kw':
                        mat = aui['I_tex']
                    else:
                        mat = aui['I_spa']
                    for binfo in buckets:
                        cols = binfo['columns']
                        bits = binfo['bits']  # list[int 0/1] for this party
                        for local_idx, col_idx in enumerate(cols):
                            if int(bits[local_idx]) == 1:
                                matrix = mat['EbW' if typ == 'kw' else 'Ebp']
                                if candidate_positions_norm is None:
                                    col_cells = [row[col_idx] for row in matrix]
                                    vec_total = xor_pair_lists(vec_total, col_cells)
                                else:
                                    for c_idx, row_idx in enumerate(candidate_positions_norm):
                                        vec_total[c_idx] = xor_bytes(vec_total[c_idx], matrix[row_idx][col_idx])
                                if sentinel_vec_total is not None:
                                    for s_idx, row_idx in enumerate(sentinel_positions_norm):
                                        sentinel_vec_total[s_idx] = xor_bytes(sentinel_vec_total[s_idx], matrix[row_idx][col_idx])
                                proof_total = xor_bytes(proof_total, mat['sigma'][col_idx])
                    # encode
                    result_shares.append([base64.b64encode(v).decode('utf-8') for v in vec_total])
                    proof_shares.append(base64.b64encode(proof_total).decode('utf-8'))
                    if sentinel_vec_total is not None:
                        sentinel_result_shares.append([base64.b64encode(v).decode('utf-8') for v in sentinel_vec_total])

                out = {"result_shares": result_shares, "proof_shares": proof_shares}
                if candidate_positions_norm is not None:
                    out["candidate_positions"] = candidate_positions_norm
                    out["candidate_fast_tag"] = base64.b64encode(_fast_subset_tag(candidate_positions_norm)).decode('utf-8')
                if sentinel_positions_norm is not None:
                    out["sentinel_positions"] = sentinel_positions_norm
                    out["sentinel_result_shares"] = sentinel_result_shares
                    out["sentinel_fast_tag"] = base64.b64encode(_fast_subset_tag(sentinel_positions_norm)).decode('utf-8')
                return self._send(200, out)
            except Exception as e:
                return self._send(500, {"error": f"eval failed: {e}"})

        return self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=8001)
    ap.add_argument('--aui', type=str, default=os.path.join(THIS_DIR, 'aui.pkl'), help='path to pickled AUI')
    ap.add_argument('--user-db', type=str, default=os.path.join(THIS_DIR, 'users_db.json'), help='path to user database json')
    args = ap.parse_args()

    with open(args.aui, 'rb') as f:
        CSPState.aui = pickle.load(f)
    ensure_user_db(args.user_db)
    CSPState.user_db_path = args.user_db
    print(
        f"[csp_server] AUI loaded. Port={args.port}. UserDB={args.user_db}. "
        f"NativeAccel={'on' if NATIVE_ACCEL_ENABLED else 'off'}"
    )

    httpd = HTTPServer(('0.0.0.0', args.port), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == '__main__':
    main()
