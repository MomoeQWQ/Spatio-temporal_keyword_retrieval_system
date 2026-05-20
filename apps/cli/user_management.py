"""Lightweight user/group management for the online demo."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, List, Tuple

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_USER_DB = os.path.join(THIS_DIR, "users_db.json")
DEFAULT_TOKEN_TTL_SECONDS = 3600
PBKDF2_ITERATIONS = 120_000


def _urlsafe_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _urlsafe_unb64(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("utf-8"))


def _hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
    return dk.hex()


def _new_password_record(password: str) -> Dict:
    salt_hex = secrets.token_hex(16)
    return {
        "salt": salt_hex,
        "hash": _hash_password(password, salt_hex),
        "iterations": PBKDF2_ITERATIONS,
    }


def verify_password(password: str, rec: Dict) -> bool:
    expected = rec.get("hash", "")
    salt_hex = rec.get("salt", "")
    if not expected or not salt_hex:
        return False
    actual = _hash_password(password, salt_hex)
    return hmac.compare_digest(actual, expected)


def _default_groups() -> Dict[str, Dict]:
    return {
        "admin": {
            "can_search": True,
            "allow_spatial": True,
            "max_keywords": 10,
            "can_manage_users": True,
            "can_manage_groups": True,
        },
        "analyst": {
            "can_search": True,
            "allow_spatial": True,
            "max_keywords": 6,
            "can_manage_users": False,
            "can_manage_groups": False,
        },
        "guest": {
            "can_search": True,
            "allow_spatial": False,
            "max_keywords": 3,
            "can_manage_users": False,
            "can_manage_groups": False,
        },
    }


def _default_users() -> Dict[str, Dict]:
    return {
        "admin": {
            "password": _new_password_record("admin123"),
            "groups": ["admin"],
            "active": True,
        },
        "alice": {
            "password": _new_password_record("alice123"),
            "groups": ["analyst"],
            "active": True,
        },
        "bob": {
            "password": _new_password_record("bob123"),
            "groups": ["guest"],
            "active": True,
        },
    }


def ensure_user_db(db_path: str = DEFAULT_USER_DB) -> None:
    if os.path.exists(db_path):
        return
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = {
        "version": 1,
        "token_secret": secrets.token_hex(32),
        "groups": _default_groups(),
        "users": _default_users(),
    }
    save_user_db(db, db_path)


def load_user_db(db_path: str = DEFAULT_USER_DB) -> Dict:
    ensure_user_db(db_path)
    with open(db_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_user_db(db: Dict, db_path: str = DEFAULT_USER_DB) -> None:
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


def merged_permissions(db: Dict, groups: List[str]) -> Dict:
    perms = {
        "can_search": False,
        "allow_spatial": False,
        "max_keywords": 0,
        "can_manage_users": False,
        "can_manage_groups": False,
    }
    groups_cfg = db.get("groups", {})
    for g in groups:
        p = groups_cfg.get(g, {})
        perms["can_search"] = perms["can_search"] or bool(p.get("can_search", False))
        perms["allow_spatial"] = perms["allow_spatial"] or bool(p.get("allow_spatial", False))
        perms["can_manage_users"] = perms["can_manage_users"] or bool(p.get("can_manage_users", False))
        perms["can_manage_groups"] = perms["can_manage_groups"] or bool(p.get("can_manage_groups", False))
        perms["max_keywords"] = max(perms["max_keywords"], int(p.get("max_keywords", 0)))
    return perms


def public_user_profile(db: Dict, username: str) -> Dict | None:
    rec = db.get("users", {}).get(username)
    if not rec:
        return None
    groups = list(rec.get("groups", []))
    return {
        "username": username,
        "groups": groups,
        "active": bool(rec.get("active", True)),
        "permissions": merged_permissions(db, groups),
    }


def issue_token(db: Dict, username: str, ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> str:
    exp = int(time.time()) + max(60, int(ttl_seconds))
    payload = {"u": username, "exp": exp}
    payload_b64 = _urlsafe_b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    secret = db.get("token_secret", "").encode("utf-8")
    sig = hmac.new(secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    return f"{payload_b64}.{_urlsafe_b64(sig)}"


def verify_token(db: Dict, token: str) -> Tuple[Dict | None, str | None]:
    if "." not in token:
        return None, "invalid auth token format"
    payload_b64, sig_b64 = token.split(".", 1)
    secret = db.get("token_secret", "").encode("utf-8")
    expected_sig = hmac.new(secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
    try:
        actual_sig = _urlsafe_unb64(sig_b64)
    except Exception:
        return None, "invalid auth token signature"
    if not hmac.compare_digest(expected_sig, actual_sig):
        return None, "auth token signature mismatch"
    try:
        payload = json.loads(_urlsafe_unb64(payload_b64).decode("utf-8"))
    except Exception:
        return None, "invalid auth token payload"
    exp = int(payload.get("exp", 0))
    if exp <= int(time.time()):
        return None, "auth token expired"
    username = str(payload.get("u", ""))
    profile = public_user_profile(db, username)
    if not profile:
        return None, "user not found"
    if not profile["active"]:
        return None, "user is inactive"
    return profile, None


def authenticate_user(db: Dict, username: str, password: str, ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> Tuple[Dict | None, str | None]:
    rec = db.get("users", {}).get(username)
    if not rec:
        return None, "user not found"
    if not bool(rec.get("active", True)):
        return None, "user is inactive"
    if not verify_password(password, rec.get("password", {})):
        return None, "invalid password"
    token = issue_token(db, username, ttl_seconds=ttl_seconds)
    profile = public_user_profile(db, username)
    return {
        "auth_token": token,
        "user": profile,
    }, None


def create_or_update_group(db: Dict, group_name: str, policy: Dict) -> None:
    db.setdefault("groups", {})
    current = db["groups"].get(group_name, {})
    merged = dict(current)
    merged.update(policy)
    merged["can_search"] = bool(merged.get("can_search", False))
    merged["allow_spatial"] = bool(merged.get("allow_spatial", False))
    merged["can_manage_users"] = bool(merged.get("can_manage_users", False))
    merged["can_manage_groups"] = bool(merged.get("can_manage_groups", False))
    merged["max_keywords"] = max(0, int(merged.get("max_keywords", 0)))
    db["groups"][group_name] = merged


def create_or_update_user(db: Dict, username: str, password: str | None, groups: List[str], active: bool = True) -> None:
    db.setdefault("users", {})
    if username in db["users"]:
        rec = db["users"][username]
    else:
        rec = {"password": _new_password_record(password or "changeme123"), "groups": [], "active": True}
        db["users"][username] = rec
    if password:
        rec["password"] = _new_password_record(password)
    rec["groups"] = list(groups)
    rec["active"] = bool(active)


def assign_groups(db: Dict, username: str, groups: List[str]) -> Tuple[bool, str]:
    rec = db.get("users", {}).get(username)
    if not rec:
        return False, "user not found"
    rec["groups"] = list(groups)
    return True, "ok"


def authorize_query(profile: Dict, tokens: List[Dict]) -> Tuple[bool, str]:
    perms = profile.get("permissions", {})
    if not bool(perms.get("can_search", False)):
        return False, "user is not allowed to search"
    kw_count = sum(1 for t in tokens if t.get("type", "kw") == "kw")
    has_spatial = any(t.get("type", "kw") == "spa" for t in tokens)
    max_keywords = int(perms.get("max_keywords", 0))
    if kw_count > max_keywords:
        return False, f"too many keywords: {kw_count} > {max_keywords}"
    if has_spatial and not bool(perms.get("allow_spatial", False)):
        return False, "user group is not allowed to issue spatial queries"
    return True, "ok"


def list_users_public(db: Dict) -> List[Dict]:
    out = []
    for username in sorted(db.get("users", {}).keys()):
        profile = public_user_profile(db, username)
        if profile:
            out.append(profile)
    return out
