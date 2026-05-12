import sys
import os
sys.path.append(os.getcwd())
from app import app, db, Server
import json

with app.app_context():
    server = Server.query.first()
    if server:
        print(f"Server: {server.hostname}")
        print(f"Old Maintenance: {server.is_maintenance}")
        server.is_maintenance = True
        server.managed_services = json.dumps([{"name": "test", "username": "root", "path": "/tmp"}])
        db.session.commit()
        
        # Reload
        db.session.refresh(server)
        print(f"New Maintenance: {server.is_maintenance}")
        print(f"New Services: {server.managed_services}")
    else:
        print("No servers found")
