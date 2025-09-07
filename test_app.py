# tests/test_app.py
from flask.testing import FlaskClient
import os, sys, importlib, uuid, pytest
from pathlib import Path

def uniq(prefix="u"): 
    return f"{prefix}_{uuid.uuid4().hex[:8]}"

# ---------- Fixture: client with fresh DB + seeded access rules ----------

@pytest.fixture(scope="function")
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Force a brand-new SQLite DB BEFORE importing app.py
    dbfile = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{dbfile}")

    # Ensure project root (folder with app.py) is importable, and reload app
    ROOT = Path(__file__).resolve().parents[1]
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    sys.modules.pop("app", None)
    app_mod = importlib.import_module("app")

    from app import app, db, AccessRule  # noqa

    # Test config + schema
    app.config.update(TESTING=True, JWT_ACCESS_TOKEN_EXPIRES=False)
    with app.app_context():
        try:
            db.drop_all()
        except Exception:
            pass
        db.create_all()

        # Seed DB-backed access rules so reads will work later
        db.session.add_all([
            AccessRule(role="friend", context="social"),
            AccessRule(role="hr",     context="legal"),
            AccessRule(role="hr",     context="social"),
            AccessRule(role="admin",  context="legal"),
            AccessRule(role="admin",  context="social"),
            AccessRule(role="admin",  context="religious"),
        ])
        db.session.commit()

        yield app.test_client()

        db.session.remove()
        db.drop_all()

# ---------- Actual tests ----------
def register(client, username, password, role="friend"):
    return client.post("/auth/register", json={"username": username, "password": password, "role": role}) # should return 201 Created

def login(client, username, password):
    return client.post("/auth/login", json={"username": username, "password": password}) # should return access_token

def test_register_and_login(client: FlaskClient):
    user = uniq("alice") # unique username per test run
    r = register(client, user, "pw", role="friend") # should return 201 Created
    print("REGISTER:", r.status_code, r.get_json()) 
    assert r.status_code == 201

    r = login(client, user, "pw") # should return access_token
    print("LOGIN:", r.status_code, r.get_json()) 
    assert r.status_code == 200
    assert "access_token" in (r.get_json() or {})
