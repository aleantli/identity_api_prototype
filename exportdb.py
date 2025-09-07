import csv
from app import app, db, UserProfile

# Export all user profiles to a CSV file
with app.app_context():
    profiles = UserProfile.query.all() # fetch all profiles
    with open("exported_profiles.csv", "w", newline='', encoding='utf-8') as csvfile: # open CSV file for writing
        writer = csv.DictWriter(csvfile, fieldnames=["username", "token", "preferred_language", "identity_data"]) # define CSV columns
        writer.writeheader() # write header row
        for p in profiles: # write each profile as a row
            writer.writerow({ # write profile data
                "username": p.username, # assuming UserProfile has a username field
                "token": p.token,
                "preferred_language": p.preferred_language,
                "identity_data": str(p.identity_data)
            })

print("Exported to exported_profiles.csv") # notify completion
