from app import app, db, User
import jwt

with app.app_context():
    # Login as admin to get a valid token
    admin = User.query.first()
    
    token = jwt.encode({"sub": str(admin.id)}, app.config["SECRET_KEY"], algorithm="HS256")
    headers = {'Authorization': f'Bearer {token}'}
    
    client = app.test_client()
        
    for url in ['/api/cases/25/details', '/api/alerts?case_id=25&limit=200', '/api/audit-logs']:
        print(f"Testing {url}...")
        try:
            res = client.get(url, headers=headers)
            print(f"Status: {res.status_code}")
            if res.status_code == 500:
                print(f"Response: {res.data.decode('utf-8')[:1000]}")
        except Exception as e:
            print(f"Exception raised: {e}")
            import traceback
            traceback.print_exc()
