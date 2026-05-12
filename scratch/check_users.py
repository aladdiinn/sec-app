import sys
import os
sys.path.append(os.getcwd())
from app import app, db
from models import User

with app.app_context():
    users = User.query.all()
    for u in users:
        print(f"ID: {u.id}, Username: {u.username}, Email: {u.email}, Role: {u.role}")
