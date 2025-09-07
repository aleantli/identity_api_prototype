import os
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt, verify_jwt_in_request
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from datetime import datetime
import types

# Flask application setup because it's lightweight and easy to control at the route level.
# SQLAlchemy is added for ORM mapping so don’t manually write SQL.
# JWT is for authentication and access control. Werkzeug is used for password hashing.

app = Flask(__name__)

# Attempt to use Postgres if DATABASE_URL is set, otherwise fall back to a local SQLite file for dev/demo.
# app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///profiles.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://dev:dev@localhost:5432/identity_db'

# Prevents unnecessary overhead from SQLAlchemy tracking modifications.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret key for JWT token signing. Hard-coded for prototype purposes.
# Must be randomized & secured in prod.
app.config['JWT_SECRET_KEY'] = 'your-very-secret-key'  

# Tokens expire after 2 hours — balances usability with security.
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)  

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Tests
# Purpose: allow a load balancer or uptime monitor to verify the
# runtime is alive.
@app.get("/healthz")
def healthz():
    # Simple health check for deployment monitoring
    return {"ok": True}, 200



# Database Models
# - User: authentication + role (friend/hr/admin)
# - UserProfile: JSON bag of identity fields grouped by context
#                (e.g., "legal", "social", "religious")
# - AccessRule: DB-driven mapping of role -> allowed context
# - AuditLog: append-only trail of reads/writes (success or deny)

class AuditLog(db.Model):

    """
    Append-only access trail to support:
      - debugging access decisions,
      - compliance/audit (e.g., GDPR-style accountability),
      - visibility into denied attempts.
    """
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(64)) 
    role = db.Column(db.String(64), nullable=False)   # Roles such as admin/friend/hr
    path = db.Column(db.String(128)) 
    context = db.Column(db.String(64), nullable=False) # Context such as "social", "legal", etc.
    action = db.Column(db.String(8), nullable=False)  
    allowed = db.Column(db.Boolean, nullable=False) 
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True) 
class User(db.Model):

    """
    Authenticated system user.
    Roles are coarse-grained and combined with AccessRule for field-level filtering.
    """
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False) # "friend" | "hr" | "admin"

    def set_password(self, pw):
        """Hash and store a password. Never store plaintext."""
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        """Verify provided password against stored hash."""
        return check_password_hash(self.password_hash, pw)


class UserProfile(db.Model):

    """
    Identity record keyed by username.
      Example:
        {
          "legal": {"name": "Bertha Ball"},
          "social": {"name": "Big Bert"},
          "religious": {"name": "Sister Bert"}
        }
    """

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    identity_data = db.Column(db.JSON)
    preferred_language = db.Column(db.String(20), default="en")
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

class AccessRule(db.Model):

    """
    DB-driven policy: which contexts a given role may access.

    """

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=False)
    context = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f"<AccessRule {self.role}:{self.context}>"

# Routes

@app.route('/')
def index():
    
    """
    Simple index that serves the demo UI. Main landing page.
    The static HTML/React app calls the API routes below.
    """

    return render_template('index.html')


# Auth: Registration (public)
@app.route('/auth/register', methods=['POST'])
def register():
    """
    Register a user with a role.
    This is simplistic by design (no email verification, etc.) for the prototype.

    """

    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "username and password required"}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "User already exists"}), 400

    user = User(username=data['username'], role=data.get('role', 'friend'))
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered"}), 201


# Auth: Login (public)
@app.route('/auth/login', methods=['POST'])
def login():
    """
    Exchange username/password for a JWT access token.
    The token embeds the user's role as a claim for quick checks at request time.
    Note: In a real system, consider rate-limiting login attempts to mitigate brute-force attacks.
    """
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Please enter your username and password!"}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({"error": "Invalid username or password!"}), 401
    
    # JWT contains role claim to avoid an extra DB lookup on every request.
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={'role': user.role}
    )
    return jsonify(access_token=access_token), 200


# # Profiles: GET (requires valid JWT)
@app.route('/api/profile/<username>', methods=['GET'])
@jwt_required()
def get_profile(username):

    """
    Return a user profile limited by the caller's role and (optionally) a context filter.
    Principle: contextual integrity — expose only fields appropriate to role/context.
    Query params:
      - context: if provided, must be allowed for the caller's role.
    """
    claims = get_jwt()
    role = claims.get('role', '')
    context = request.args.get("context", None)

    profile = UserProfile.query.filter_by(username=username).first()
    if not profile:
        return jsonify({'error': f'Profile for {username} not found.'}), 404

    data = profile.identity_data or {}

    # Admins can read everything
    if role == 'admin':
        if context:
            audit_log(context, "READ", True)
            return jsonify({context: data.get(context)}), 200
        audit_log("all", "READ", True)
        return jsonify(data), 200
    
    # Pull allowed contexts for this role from the DB.
    rule_objs = AccessRule.query.filter_by(role=role).all()
    allowed_contexts = [r.context for r in rule_objs]

    # Case A: Specific context requested
    if context:
        if context not in allowed_contexts:
            # Denied attempts are logged too (important for auditing).
            audit_log(context, "READ", False)   
            return jsonify({'error': 'Forbidden: context not allowed'}), 403

        audit_log(context, "READ", True)        
        # Return the requested section only; if missing, returns null by design.
        return jsonify({context: data.get(context)}), 200

    # Case B: No context requested -> filter whole profile down to allowed contexts.
    filtered = {k: v for k, v in data.items() if k in allowed_contexts}
    audit_log("all", "READ", True)             
    return jsonify(filtered), 200


# Profiles: POST/PUT (admin only)
@app.route('/api/profile/<username>', methods=['POST', 'PUT'])
@jwt_required()
def update_profile(username):

    """
    Create or update a user's profile.
    Only admins can write. Log both allowed and denied attempts.
    """

    role = get_jwt().get('role', '')
    data = request.get_json() or {}

    if role != 'admin':
        # Cannot predict affected sub-contexts -> record "*" to indicate a write attempt.
        audit_log("*", "WRITE", False)          
        return jsonify({"error": "Forbidden: only admin can modify profiles!"}), 403

    profile = UserProfile.query.filter_by(username=username).first()
    if not profile:
        profile = UserProfile(username=username)

    # Replace identity_data wholesale for simplicity (fits demo), but a production system would likely support patch/merge semantics.
    profile.identity_data = data.get("identity_data", {})
    profile.preferred_language = data.get("preferred_language", profile.preferred_language)
    profile.last_updated = datetime.utcnow()

    db.session.add(profile)
    db.session.commit()

    audit_log("*", "WRITE", True)              
    return jsonify({"message": "Profile updated successfully"}), 200

# Profiles: LIST (role-filtered & admin-only)
@app.route('/api/profiles', methods=['GET'])
@jwt_required()
def list_profiles():
    """
    List many profiles at once, still respecting role-based context filtering.
    Optional query params:
      - context: if provided, only that slice is returned per user (must be allowed).
    """
    claims = get_jwt()
    role = claims.get("role")

    rules = AccessRule.query.filter_by(role=role).all()
    allowed = {r.context for r in rules}

    context = request.args.get("context")
    if context:
        if context not in allowed:
            audit_log(context, "READ", False)   
            return jsonify({"error": "Forbidden: context not allowed"}), 403
        # Return just the requested slice for every user.
        items = [
            {"username": p.username, context: (p.identity_data or {}).get(context)}
            for p in UserProfile.query.all()
        ]
        audit_log(context, "READ", True)       
    else:
        # Return all allowed slices for each user.
        items = []
        for p in UserProfile.query.all():
            data = p.identity_data or {}
            filtered = {k: v for k, v in data.items() if k in allowed}
            items.append({"username": p.username, **filtered})
        audit_log("all", "READ", True)          

    return jsonify(items), 200

# Request-scoped helpers
def current_user():
    """
    Try to extract a logical 'current user' for logging purposes.
    Priority order:
      1) Real JWT (preferred): get sub + role from claims.
      2) Dev bearer tokens (optional convenience): "token-admin" / "token-friend".
         This keeps local curl/Postman tests ergonomic.
    """
    try:
        # optional=True lets this function be used both inside/outside @jwt_required views
        verify_jwt_in_request(optional=True)
        try:
            claims = get_jwt() or {}
        except Exception:
            claims = {}
        uid = claims.get("sub") or claims.get("identity")
        role = claims.get("role") or "stranger"
        if role:
            return types.SimpleNamespace(id=uid, role=role)
    except Exception:
        # Fall through to dev token parsing below.
        pass 

    # Lightweight dev fallback using static bearer strings.
    auth = (request.headers.get("Authorization", "") or "").split()
    token = auth[1] if len(auth) == 2 and auth[0].lower() == "bearer" else ""
    role = "stranger"
    if token == "token-admin":
        role = "admin"
    elif token == "token-friend":
        role = "friend"
    return types.SimpleNamespace(id=None, role=role)


def audit_log(context: str, action: str, allowed: bool):

    """
    Append an entry to the audit trail.
    Commit immediately so deny events aren't lost on later transaction errors.
    """
    u = current_user()
    row = AuditLog(
        user_id=getattr(u, "id", None),
        role=getattr(u, "role", "stranger") or "stranger",
        path=request.path,
        context=context,
        action=action,
        allowed=allowed,
    )
    db.session.add(row)
    db.session.commit()  # commit immediately so denied logs persist

# Audit logs API (admin-only)
@app.get("/api/audit-logs")
@jwt_required()
def list_audit_logs():

    """
    Paginated(ish) view of recent audit events. Admin-only by design.
    Filters:
      - limit: cap number of rows (default 100, max 500)
      - allowed: "true"/"false"
      - context: restrict to a specific context string
      - from / to: ISO Local "YYYY-MM-DDTHH:MM" time range
    """
    if get_jwt().get("role") != "admin":
        return jsonify({"error": "admin-only"}), 403

    limit = min(int(request.args.get("limit", 100)), 500)
    allowed_q = request.args.get("allowed")        # "true"/"false"/None
    context_q = request.args.get("context")        # string or None
    ts_from   = request.args.get("from")           # "YYYY-MM-DDTHH:MM"
    ts_to     = request.args.get("to")             # "YYYY-MM-DDTHH:MM"

    q = AuditLog.query
    if allowed_q in ("true", "false"):
        q = q.filter(AuditLog.allowed == (allowed_q == "true"))
    if context_q:
        q = q.filter(AuditLog.context == context_q)
    if ts_from:
        q = q.filter(AuditLog.timestamp >= datetime.fromisoformat(ts_from))
    if ts_to:
        q = q.filter(AuditLog.timestamp <= datetime.fromisoformat(ts_to))

    rows = q.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return jsonify([
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat() + "Z", # UTC-ish indicator for consistency in UI
            "user_id": r.user_id,
            "role": r.role,
            "path": r.path,
            "context": r.context,
            "action": r.action,
            "allowed": r.allowed,
        } for r in rows
    ])

# Admin: Reset endpoints
# Supports either full wipe (all contexts) or selective context removal.

@app.post("/api/profile/<string:username>/reset")
@jwt_required()
def reset_profile(username):
    """
    Admin-only endpoint to clear identity data:
      - If body has {"contexts": ["social","legal"]} → delete only those keys
      - Else → delete everything (identity_data = {})
    """
    
    role = get_jwt().get("role", "")
    if role != "admin":
        audit_log("*", "WRITE", False)
        return jsonify({"error": "Forbidden: only admin can reset profiles"}), 403

    profile = UserProfile.query.filter_by(username=username).first()
    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    payload = request.get_json(silent=True) or {}
    contexts = payload.get("contexts")  # list of strings, optional

    data = (profile.identity_data or {}).copy()
    if contexts and isinstance(contexts, list):
        cleared = []
        for c in contexts:
            if c in data:
                data.pop(c, None)
                cleared.append(c)
        profile.identity_data = data
        profile.last_updated = datetime.utcnow()
        db.session.add(profile)
        db.session.commit()
        audit_log(",".join(cleared) if cleared else "*", "WRITE", True)
        return jsonify({"message": "Selected contexts cleared", "cleared": cleared}), 200
    else:
        # Clear EVERYTHING
        profile.identity_data = {}
        profile.last_updated = datetime.utcnow()
        db.session.add(profile)
        db.session.commit()
        audit_log("*", "WRITE", True)
        return jsonify({"message": "All contexts cleared"}), 200

# Admin: Access rules management
# - List all rules (admin sees all; others see only their role's rules)
@app.get("/api/access-rules")
@jwt_required()
def list_access_rules():
    # let admin list everything; others can only see their own role’s rows
    role = get_jwt().get("role", "")
    q = AccessRule.query
    if role != "admin":
        # non-admins see only their role’s rules
        q = q.filter_by(role=role)
    rows = q.order_by(AccessRule.role, AccessRule.context).all()
    return jsonify([{"id": r.id, "role": r.role, "context": r.context} for r in rows]), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # creates tables if they don't exist; safe for local dev
    
    # debug=True for developer ergonomics; disable in production.    
    app.run(debug=True)


