import unittest
from app import app, db
from models import User
import json

class SecurePulseTestCase(unittest.TestCase):
    def setUp(self):
        # Set up a test client and configure the app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        
        # Create all tables in the in-memory database
        with app.app_context():
            db.create_all()
            # Seed a test admin
            from werkzeug.security import generate_password_hash
            admin = User(
                email='testadmin@securepulse.local',
                hashed_password=generate_password_hash('TestAdmin@123'),
                full_name='Test Admin',
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

    def tearDown(self):
        # Clean up the database
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_login_page_loads(self):
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'SecurePulse', response.data)

    def test_dashboard_redirects_unauthenticated(self):
        response = self.app.get('/dashboard')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers.get('Location', ''))

    def test_login_api_success(self):
        response = self.app.post('/auth/login', json={
            'email': 'testadmin@securepulse.local',
            'password': 'TestAdmin@123'
        })
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('access_token', data)

    def test_login_api_failure(self):
        response = self.app.post('/auth/login', json={
            'email': 'testadmin@securepulse.local',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()
