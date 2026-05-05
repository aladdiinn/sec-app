from flask import Flask
from flask_sqlalchemy import SQLAlchemy # type: ignore

# Initialize the SQLAlchemy object
db = SQLAlchemy()

def init_db(app: Flask):
    """
    Initializes the database schema.
    Ensures all tables defined in models.py are created in PostgreSQL.
    """
    with app.app_context():
        # This will create tables for all models registered with 'db'
        db.create_all()