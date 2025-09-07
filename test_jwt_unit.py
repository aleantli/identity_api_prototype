# tests/test_jwt_unit.py
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, decode_token

# ---------- Actual test ----------
def test_jwt_roundtrip():
    app = Flask(__name__) # create a minimal Flask app
    app.config["JWT_SECRET_KEY"] = "test-secret" # change this secret key in prod!
    JWTManager(app) # setup the Flask-JWT-Extended extension

    with app.app_context(): # app context needed for JWTs
        token = create_access_token(identity="123", additional_claims={"role": "friend"})
        decoded = decode_token(token) 
        # show a bit of output (header part of JWT)
        print("JWT header piece:", token.split(".")[0])
        assert decoded["sub"] == "123"
        assert decoded["role"] == "friend"
