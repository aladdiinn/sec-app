from app import app, db
from models import User

with app.app_context():
    # Find the admin by email and ensure the username is 'admin'
    admin_email = "admin@securepulse.local"
    user = User.query.filter_by(email=admin_email).first()
    if user:
        user.username = "admin"
        db.session.commit()
        print(f"Successfully updated {admin_email} with username 'admin'")
    else:
        # If no user exists, seed_admin should have handled it, but let's be sure
        from app import seed_admin
        seed_admin()
        print("Admin user not found by email, ran seed_admin instead.")
