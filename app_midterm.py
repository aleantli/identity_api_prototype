from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///profiles.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Token to role mapping
user_roles = {
    "token1": "friend",
    "token2": "hr",
    "token3": "admin"
}

# Role-based context access
access_matrix = {
    "friend": ["social"],
    "hr": ["legal", "social"],
    "admin": ["legal", "social", "religious"]
}

@app.route('/')
def index():
    return render_template('index.html')

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    token = db.Column(db.String(80), nullable=False)
    identity_data = db.Column(db.JSON)
    preferred_language = db.Column(db.String(20))
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)

# Authentication
def authenticate(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or token not in user_roles:
            return jsonify({"error": "Unauthorized"}), 401
        request.user_role = user_roles[token]
        request.user_token = token
        return f(*args, **kwargs)
    return decorated_function

# GET route
@app.route('/api/profile/<username>', methods=['GET'])
@authenticate
def get_profile(username):
    context = request.args.get("context")
    profile = UserProfile.query.filter_by(username=username).first()
    if not profile:
        return jsonify({'error': 'Profile not found'}), 404

    data = profile.identity_data
    role = request.user_role
    allowed_fields = access_matrix.get(role, [])

    if context and context in allowed_fields:
        return jsonify({context: data.get(context)})
    filtered = {k: v for k, v in data.items() if k in allowed_fields}
    return jsonify(filtered)

# POST/PUT route
@app.route('/api/profile/<username>', methods=['POST', 'PUT'])
@authenticate
def update_profile(username):
    if request.user_role != "admin":
        return jsonify({"error": "Forbidden. Only admin can write data."}), 403

    data = request.get_json()
    profile = UserProfile.query.filter_by(username=username).first()
    if not profile:
        profile = UserProfile(username=username, token=request.user_token)

    profile.identity_data = data.get("identity_data", {})
    profile.preferred_language = data.get("preferred_language", "en")
    profile.last_updated = datetime.utcnow()

    db.session.add(profile)
    db.session.commit()

    return jsonify({"message": "Profile saved successfully"})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
