# --- ensure project root is on sys.path ---
import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path: sys.path.insert(0, ROOT)
# -----------------------------------------

# tests/test_profiles.py
import json
import time
import pytest

# Import your Flask app + db + models
from app import app, db, User, UserProfile, AccessRule, AuditLog

# ---------- Helpers ----------

def seed_access_rules(): 
    """
    DB-driven rules used by app.py:
      friend  -> social
      hr      -> social, legal
      admin   -> social, legal, religious
    """
    rules = [ # (role, context) pairs
        ("friend", "social"),
        ("hr", "social"), ("hr", "legal"),
        ("admin", "social"), ("admin", "legal"), ("admin", "religious"),
    ]
    for role, ctx in rules: 
        db.session.add(AccessRule(role=role, context=ctx)) # add if not exists
    db.session.commit()

# ---------- API helpers ----------
def register_user(client, username, password, role): # returns response
    resp = client.post("/auth/register", json={  # should return 201 Created
        "username": username,
        "password": password,
        "role": role
    })
    return resp # response object

def login_user(client, username, password): # returns access token string
    resp = client.post("/auth/login", json={ # should return access_token
        "username": username,
        "password": password
    })
    assert resp.status_code == 200, f"Login failed: {resp.status_code} {resp.get_data(as_text=True)}" # should succeed
    token = resp.get_json()["access_token"]
    return token

# Helper to create auth headers
def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}

# ---------- Fixtures ----------

@pytest.fixture(scope="function")
def client():
    """
    Fresh DB per test:
    - drops & recreates tables
    - seeds access rules
    - yields Flask test client
    """
    with app.app_context(): # app context needed for DB ops
        db.drop_all() # drop any existing tables
        db.create_all() # create tables
        seed_access_rules() # seed access rules
        yield app.test_client() # yield Flask test client for use in tests

# ---------- Tests ----------

def test_register_and_login_smoke(client): # basic register+login smoke test
    r = register_user(client, "admin1", "pw", "admin") 
    assert r.status_code == 201
    token = login_user(client, "admin1", "pw")
    assert isinstance(token, str) and token.count(".") == 2  # looks like a JWT


def test_admin_create_profile_and_read(client): # admin creates profile, reads it back
    # admin login
    register_user(client, "admin1", "pw", "admin")
    admin_token = login_user(client, "admin1", "pw")

    # create a profile for "alice"
    payload = {"identity_data": {"social": "Ally", "legal": "Alice L", "religious": "Sister A"}} # full data
    resp = client.post("/api/profile/alice", json=payload, headers=auth_headers(admin_token)) # should succeed
    assert resp.status_code == 200

    # admin can read all contexts
    resp = client.get("/api/profile/alice", headers=auth_headers(admin_token)) # read all
    data = resp.get_json() # should return full data
    assert resp.status_code == 200
    assert data == {"social": "Ally", "legal": "Alice L", "religious": "Sister A"}

    # and specific context
    resp = client.get("/api/profile/alice?context=legal", headers=auth_headers(admin_token))
    assert resp.status_code == 200
    assert resp.get_json() == {"legal": "Alice L"}


def test_non_admin_cannot_write(client): # friend cannot create/update profile
    # seed admin & create profile
    register_user(client, "friend1", "pw", "friend") # friend user
    friend_tok = login_user(client, "friend1", "pw") # login friend

    resp = client.post("/api/profile/bob", json={"identity_data": {"social": "Bobby"}}, 
                       headers=auth_headers(friend_tok)) # should be forbidden
    assert resp.status_code == 403
    body = resp.get_json() 
    assert "only admin" in (body.get("error") or "").lower() # error message


def test_friend_can_read_only_social(client): # friend can read only 'social' context
    # seed admin & create profile
    register_user(client, "admin1", "pw", "admin")
    admin_tok = login_user(client, "admin1", "pw")
    client.post("/api/profile/cara", json={"identity_data": {"social": "C", "legal": "Cara L", "religious": "Sister C"}},
                headers=auth_headers(admin_tok)) # create profile

    # friend login
    register_user(client, "friend1", "pw", "friend") 
    friend_tok = login_user(client, "friend1", "pw")

    # friend reading all -> only social should be returned
    resp = client.get("/api/profile/cara", headers=auth_headers(friend_tok))
    assert resp.status_code == 200
    assert resp.get_json() == {"social": "C"}

    # friend requesting legal explicitly -> 403
    resp = client.get("/api/profile/cara?context=legal", headers=auth_headers(friend_tok))
    assert resp.status_code == 403


def test_hr_can_read_legal_and_social(client): # HR can read 'legal' and 'social' contexts
    # create profile as admin
    register_user(client, "admin1", "pw", "admin")
    admin_tok = login_user(client, "admin1", "pw")
    client.post("/api/profile/dan", json={"identity_data": {"social": "Danny", "legal": "Daniel P", "religious": "Brother D"}},
                headers=auth_headers(admin_tok))

    register_user(client, "hr1", "pw", "hr") # create HR user
    hr_tok = login_user(client, "hr1", "pw") # login HR

    # all (allowed) for HR -> legal+social only
    resp = client.get("/api/profile/dan", headers=auth_headers(hr_tok)) # no context param
    assert resp.status_code == 200 # should succeed
    assert resp.get_json() == {"social": "Danny", "legal": "Daniel P"} # only social+legal

    # religious explicitly -> 403
    resp = client.get("/api/profile/dan?context=religious", headers=auth_headers(hr_tok))
    assert resp.status_code == 403


def test_list_profiles_admin_and_friend(client): # admin and friend list profiles, see allowed contexts
    # create two profiles as admin
    register_user(client, "admin1", "pw", "admin") # admin user
    admin_tok = login_user(client, "admin1", "pw") # login admin

    client.post("/api/profile/p1", json={"identity_data": {"social": "S1", "legal": "L1", "religious": "R1"}},
                headers=auth_headers(admin_tok)) # create profile 1
    client.post("/api/profile/p2", json={"identity_data": {"social": "S2", "legal": "L2", "religious": "R2"}},
                headers=auth_headers(admin_tok)) # create profile 2

    # admin list -> all contexts
    resp = client.get("/api/profiles", headers=auth_headers(admin_tok))
    assert resp.status_code == 200
    rows = resp.get_json() # list of profiles
    assert {r["username"] for r in rows} == {"p1", "p2"} # both present
    for r in rows: 
        assert "social" in r and "legal" in r and "religious" in r # all present

    # friend list -> only social
    register_user(client, "friend1", "pw", "friend") # create friend user
    f_tok = login_user(client, "friend1", "pw") # login friend
    resp = client.get("/api/profiles", headers=auth_headers(f_tok)) # list profiles
    assert resp.status_code == 200 # should succeed
    rows = resp.get_json() # list of profiles
    for r in rows:
        assert "social" in r and "legal" not in r and "religious" not in r


def test_forbidden_context_is_logged(client): # friend tries to read forbidden context, admin checks audit log
    # create profile
    register_user(client, "admin1", "pw", "admin") # admin user
    admin_tok = login_user(client, "admin1", "pw") # login admin
    client.post("/api/profile/eve", json={"identity_data": {"social": "Evie", "legal": "Evelyn T"}}, # create profile
                headers=auth_headers(admin_tok))

    # friend attempts forbidden context
    register_user(client, "friend1", "pw", "friend") # create friend user
    friend_tok = login_user(client, "friend1", "pw") # login friend
    resp = client.get("/api/profile/eve?context=legal", headers=auth_headers(friend_tok)) # should be forbidden
    assert resp.status_code == 403

    # admin can see an audit log with allowed=false
    resp = client.get("/api/audit-logs?allowed=false&limit=50", headers=auth_headers(admin_tok))
    assert resp.status_code == 200
    logs = resp.get_json()
    # At least one denied READ on 'legal'
    assert any((l["action"] == "READ" and l["allowed"] is False and l["context"] == "legal") for l in logs)


def test_reset_profile_clear_selected(client): # admin clears selected contexts from profile
    # create profile
    register_user(client, "admin1", "pw", "admin")
    admin_tok = login_user(client, "admin1", "pw")
    client.post("/api/profile/frank", json={"identity_data": {"social": "F", "legal": "Frank L", "religious": "Brother F"}},
                headers=auth_headers(admin_tok))

    # clear only 'social' + 'religious'
    resp = client.post("/api/profile/frank/reset",
                       json={"contexts": ["social", "religious"]},
                       headers=auth_headers(admin_tok))
    assert resp.status_code == 200

    # verify remaining fields
    resp = client.get("/api/profile/frank", headers=auth_headers(admin_tok))
    assert resp.get_json() == {"legal": "Frank L"}


def test_reset_profile_clear_all(client): # admin clears all contexts from profile
    register_user(client, "admin1", "pw", "admin")
    admin_tok = login_user(client, "admin1", "pw")
    client.post("/api/profile/grace", json={"identity_data": {"social": "G", "legal": "Grace L"}},
                headers=auth_headers(admin_tok))

    # clear everything (no contexts payload)
    resp = client.post("/api/profile/grace/reset", json={}, headers=auth_headers(admin_tok))
    assert resp.status_code == 200

    resp = client.get("/api/profile/grace", headers=auth_headers(admin_tok))
    assert resp.status_code == 200
    assert resp.get_json() == {}  # all wiped


def test_audit_logs_admin_only(client): # only admin can read audit logs
    # admin and friend users
    register_user(client, "admin1", "pw", "admin") # admin user
    admin_tok = login_user(client, "admin1", "pw")
    register_user(client, "friend1", "pw", "friend") # friend user
    friend_tok = login_user(client, "friend1", "pw")

    # friend blocked
    resp = client.get("/api/audit-logs", headers=auth_headers(friend_tok)) # should be forbidden
    assert resp.status_code == 403

    # admin allowed
    resp = client.get("/api/audit-logs?limit=10", headers=auth_headers(admin_tok)) # should succeed
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)
