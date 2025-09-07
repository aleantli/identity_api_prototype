from app import app, db, UserProfile

with app.app_context():
    profiles = UserProfile.query.all()
    for profile in profiles:
        print(f"Username: {profile.username}")
        print(f"Token: {profile.token}")
        print(f"Data: {profile.identity_data}")
        print(f"Language: {profile.preferred_language}")
        print("---")
