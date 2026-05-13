from app import app
from database import init_db

print("Starting init_db test")
with app.app_context():
    init_db(app)
print("init_db finished successfully")
