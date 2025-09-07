# tests/test_unit_smoke.py
import json
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- Actual tests ----------
def test_math_basics():
    a, b = 2, 3
    s = a + b
    print("Sum:", a, "+", b, "=", s)
    assert s == 5


def test_string_ops(): # simple string manipulation test
    text = "  hello World  " # sample input
    cleaned = text.strip().title() # clean it up
    print("Original:", repr(text), "-> Cleaned:", cleaned)  # use ASCII arrow
    assert cleaned == "Hello World" # check result


def test_json_roundtrip():
    obj = {"user": "alex", "roles": ["friend", "hr"], "ok": True} # sample data
    payload = json.dumps(obj) # serialize to JSON string
    back = json.loads(payload) # deserialize back to Python object
    print("JSON length:", len(payload)) # visible output in -s mode
    assert back == obj 
    assert "roles" in back and back["ok"] is True

def test_password_hash_unit(): # simple password hashing test
    pw = "s3cret!"
    h = generate_password_hash(pw) # hash the password
    print("Hash prefix:", h.split("$", 1)[0])  # visible output in -s mode
    assert h != pw # not the same as plain text
    assert check_password_hash(h, pw) # correct password
    assert not check_password_hash(h, "wrong") # incorrect password
