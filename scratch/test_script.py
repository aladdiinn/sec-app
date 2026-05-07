import requests
import json
import time

BASE_URL = "http://127.0.0.1:5001"
EMAIL = "admin@securepulse.local"
PASSWORD = "Admin@1234"

def test_app():
    print("Testing SecurePulse App...")
    session = requests.Session()
    
    # 1. Test Login API
    print(f"Testing login at {BASE_URL}/auth/login")
    login_data = {
        "email": EMAIL,
        "password": PASSWORD
    }
    post_response = session.post(f"{BASE_URL}/auth/login", json=login_data)
    if post_response.status_code != 200:
        print(f"FAILED: Login POST returned status {post_response.status_code}")
        print(post_response.text)
        return
    else:
        print("Login POST returned status 200")
        print("Response JSON:", post_response.json())
    
    # 2. Test Pages
    urls_to_test = [
        "/",
        "/dashboard",
        "/events",
        "/alerts",
        "/incidents",
        "/assets",
        "/threat-intel",
        "/rules",
        "/playbooks",
        "/search",
        "/audit-log"
    ]
    
    print("\nTesting Pages:")
    for url in urls_to_test:
        full_url = f"{BASE_URL}{url}"
        try:
            # allow_redirects=False to see if it redirects us to login (meaning auth failed)
            resp = session.get(full_url, allow_redirects=False)
            print(f"GET {url}: Status {resp.status_code} - Length: {len(resp.text)}")
            if resp.status_code in [301, 302]:
                print(f"  -> Redirects to: {resp.headers.get('Location')}")
            if resp.status_code == 500:
                print("=============================")
                print(f"500 ERROR ON {url}:")
                print(resp.text[:500])
                print("=============================")
        except Exception as e:
            print(f"GET {url}: FAILED with exception {e}")

if __name__ == "__main__":
    test_app()
