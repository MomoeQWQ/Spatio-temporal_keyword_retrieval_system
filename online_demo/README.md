# Online Demo (Client + CSPs + Initial User RBAC)

## 1) Build index artifacts
```bash
python online_demo/owner_setup.py
```
This produces `online_demo/aui.pkl` and `online_demo/K.pkl`.

## 2) Quick run with auth-enabled defaults
```bash
python online_demo/run_all.py "ORLANDO; R: 28.3,-81.5,28.7,-81.2"
```
`run_all.py` starts 3 CSP nodes (`8001/8002/8003`) and runs the client with default user `alice/alice123`.

## 3) Run as a different user/group
```bash
python online_demo/run_all.py --username bob --password bob123 "ORLANDO"
```

## 3.1) Expansion + priority ranking
`online_demo/client.py` now supports platform-style ranking on top of expansion recall:
```bash
python online_demo/client.py \
  --query "ORLANDO UNIVERSITY; R: 28.2,-81.6,28.8,-81.1" \
  --expansion-mode fallback \
  --top-k 20
```
Optional expansion backends:
- `--expansion-mode none` : only base query.
- `--expansion-mode fallback` : local synonym expansion.
- `--expansion-mode gemini` : Gemini expansion (falls back automatically if unavailable).

Priority score is a weighted sum of:
- base-query hit bonus (`base_query_hit=80`)
- expansion-subquery hit bonus (`expansion_query_hit=22`)
- exact token match in `NAME`/`ADDRESS,CITY,STATE`
- synonym token match in `NAME`/`ADDRESS,CITY,STATE`
- exact/synonym token coverage
- ordered phrase bonus in `NAME`
- spatial range bonus when coordinates are inside query `R:`.

## 4) New local simulation for group-based communication
```bash
python online_demo/simulate_group_queries.py
```
This script:
- starts local CSP servers,
- logs in as `admin`,
- creates a new group and user online (`power_user` / `charlie`),
- runs cross-group query checks (allowed and denied scenarios).

## Optional C++ acceleration (same project layout)
Build the optional native module in-place:
```bash
python setup_native_accel.py build_ext --inplace --compiler=mingw32
```
If the native module is not built, the system automatically falls back to pure Python.

## Default demo accounts
- `admin / admin123` (can manage users and groups)
- `alice / alice123` (analyst group, spatial query allowed)
- `bob / bob123` (guest group, spatial query denied)

## Server endpoints (initial implementation)
- `POST /auth/login` - username/password login, returns signed `auth_token`.
- `POST /auth/whoami` - get user profile from token.
- `POST /admin/create_group` - upsert group policy (`can_manage_groups` required).
- `POST /admin/create_user` - upsert user (`can_manage_users` required).
- `POST /admin/assign_groups` - update user groups (`can_manage_users` required).
- `POST /admin/list_users` - list users (`can_manage_users` required).
- `POST /admin/list_groups` - list groups (`can_manage_groups` required).
- `POST /eval` - secure search execution, now requires `auth_token`.

## Internal layout note
- `online_demo/runtime_utils.py` centralizes shared HTTP/login/CSP-process helpers.
- `client.py`, `run_all.py`, and `simulate_group_queries.py` reuse this module to reduce duplicated path/network code.

## Request sequence diagram
```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant C as Client (online_demo/client.py)
    participant S1 as CSP-1
    participant S2 as CSP-2
    participant S3 as CSP-3
    participant DB as users_db.json

    U->>C: Input query + credentials
    C->>S1: POST /auth/login (username, password)
    S1->>DB: Load user + verify password
    DB-->>S1: User profile + groups
    S1-->>C: auth_token (signed, exp)

    C->>C: Build query plan (DMPF shares per party)
    par Per-party eval
        C->>S1: POST /eval (party_id=0, tokens, auth_token)
        S1->>DB: Verify token + merge group permissions
        S1-->>C: result_shares[0], proof_shares[0]
    and
        C->>S2: POST /eval (party_id=1, tokens, auth_token)
        S2->>DB: Verify token + authorize query
        S2-->>C: result_shares[1], proof_shares[1]
    and
        C->>S3: POST /eval (party_id=2, tokens, auth_token)
        S3->>DB: Verify token + authorize query
        S3-->>C: result_shares[2], proof_shares[2]
    end

    C->>C: XOR combine shares + decrypt matches + FX/HMAC verify
    C-->>U: Verify pass/fail + match list

    alt Permission denied (e.g., guest spatial query)
        S2-->>C: 403 forbidden
        C-->>U: Error: not allowed to issue spatial queries
    end
```

## Group permission model (demo version)
Each group can define:
- `can_search`
- `allow_spatial`
- `max_keywords`
- `can_manage_users`
- `can_manage_groups`

Request authorization is checked in `/eval` before CSP share computation.
