import traceback
from fastapi import Request
from starlette.datastructures import Headers
import app

req = Request({"type": "http", "headers": Headers(raw=[]), "session": {}})

for t in ["maintenance.html", "servers.html", "login.html", "dashboard.html", "users.html", "approvals.html"]:
    try:
        res = app.render_template(req, t)
        print(f"Template {t}: OK")
    except Exception as e:
        print(f"Template {t}: ERROR ({e})")
        traceback.print_exc()
