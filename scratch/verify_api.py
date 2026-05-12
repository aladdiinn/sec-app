import requests
import json

base_url = "http://127.0.0.1:5001"

def test_save_playbook():
    # 1. Login
    login_url = f"{base_url}/auth/login"
    login_data = {"username": "admin", "password": "Admin@1234"}
    
    print(f"Logging in to {login_url}...")
    try:
        r = requests.post(login_url, json=login_data)
        r.raise_for_status()
        token = r.json()["access_token"]
        print("Login successful.")
    except Exception as e:
        print(f"Login failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        return

    # 2. Save Playbook
    pb_url = f"{base_url}/api/playbooks"
    pb_data = {
        "name": "Verification Playbook",
        "description": "Created by verification script",
        "actions": [{"type": "disable_account"}]
    }
    headers = {"Authorization": f"Bearer {token}"}
    
    print(f"Saving playbook to {pb_url}...")
    try:
        r = requests.post(pb_url, json=pb_data, headers=headers)
        print(f"Status Code: {r.status_code}")
        print(f"Response: {r.text}")
        if r.status_code == 201:
            print("Playbook saved successfully!")
        else:
            print("Failed to save playbook.")
    except Exception as e:
        print(f"Error saving playbook: {e}")

if __name__ == "__main__":
    test_save_playbook()
