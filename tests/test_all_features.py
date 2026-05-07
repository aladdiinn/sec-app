import unittest
import json
from app import app, db
from models import User, Server, Event, Alert, Case, Playbook

class SecurePulseComprehensiveTest(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['AGENT_API_KEY'] = 'test-api-key'
        self.app = app.test_client()
        
        with app.app_context():
            db.create_all()
            from werkzeug.security import generate_password_hash
            # Create an admin user
            admin = User(
                email='admin@securepulse.local',
                hashed_password=generate_password_hash('Admin@123'),
                full_name='Test Admin',
                is_admin=True
            )
            db.session.add(admin)
            
            # Create a test server
            server = Server(
                hostname='test-server-01',
                ip_address='192.168.1.10',
                os_info='Linux test-server-01 5.15.0',
                agent_token='test-agent-token',
                status='online'
            )
            db.session.add(server)
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def login(self):
        return self.app.post('/auth/login', json={
            'email': 'admin@securepulse.local',
            'password': 'Admin@123'
        })

    def test_1_authentication(self):
        # Test Login
        response = self.login()
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('access_token', data)
        token = data['access_token']

        # Test Auth Me
        response = self.app.get('/auth/me', headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.data)['email'], 'admin@securepulse.local')

    def test_2_agent_registration(self):
        # Test missing API key
        res = self.app.post('/api/agents/register', json={
            'hostname': 'new-server',
            'ip_address': '10.0.0.5',
            'os_info': 'Ubuntu 22.04'
        })
        self.assertEqual(res.status_code, 401)

        # Test valid API key
        res = self.app.post('/api/agents/register', headers={'X-API-Key': 'test-api-key'}, json={
            'hostname': 'new-server',
            'ip_address': '10.0.0.5',
            'os_info': 'Ubuntu 22.04'
        })
        self.assertEqual(res.status_code, 201)
        data = json.loads(res.data)
        self.assertIn('agent_token', data)
        self.assertIn('server_id', data)

    def test_3_event_ingestion(self):
        # Ingest an event with the test server's agent token
        res = self.app.post('/api/events', headers={'X-Agent-Token': 'test-agent-token'}, json={
            'event_type': 'ssh_login',
            'severity': 'info',
            'source': 'auth.log',
            'description': 'Successful SSH login for user admin',
            'raw_data': {'user': 'admin', 'ip': '192.168.1.100'}
        })
        self.assertEqual(res.status_code, 200)
        
        # Verify event was saved
        with app.app_context():
            event = Event.query.first()
            self.assertIsNotNone(event)
            self.assertEqual(event.event_type, 'ssh_login')

    def test_4_critical_event_detection(self):
        # The app auto-flags events containing keywords like 'root' as critical
        res = self.app.post('/api/events', headers={'X-Agent-Token': 'test-agent-token'}, json={
            'event_type': 'file_change',
            'severity': 'warning',
            'description': 'File /etc/shadow was modified by root',
            'raw_data': {'file': '/etc/shadow'}
        })
        self.assertEqual(res.status_code, 200)
        
        with app.app_context():
            event = Event.query.order_by(Event.id.desc()).first()
            # Despite passing 'warning', the system should elevate to 'critical' because of 'root' and '/etc/shadow'
            self.assertEqual(event.severity, 'critical')

    def test_5_playbook_runner(self):
        with app.app_context():
            playbook = Playbook(
                name="Auto-Isolate Host",
                description="Isolate compromised host",
                actions=json.dumps([{"type": "isolate_host"}])
            )
            db.session.add(playbook)
            
            # Create an alert tied to our test server
            alert = Alert(
                server_id=1,
                alert_type="malware_detected",
                severity="critical",
                title="Ransomware behavior detected",
                message="Suspicious encryption pattern"
            )
            db.session.add(alert)
            db.session.commit()
            
            from app import PlaybookRunner
            success = PlaybookRunner.run(playbook.id, alert.id)
            self.assertTrue(success)
            
            # Verify server is isolated
            server = Server.query.get(1)
            self.assertEqual(server.status, "isolated")

    def test_6_ui_endpoints(self):
        # We must login to set the session for UI endpoints
        self.login()
        
        endpoints = [
            '/dashboard', '/incidents', '/assets', '/threat-intel', 
            '/rules', '/playbooks', '/search', '/audit-log'
        ]
        
        for endpoint in endpoints:
            res = self.app.get(endpoint)
            self.assertEqual(res.status_code, 200, f"Endpoint {endpoint} failed")

if __name__ == '__main__':
    unittest.main()
