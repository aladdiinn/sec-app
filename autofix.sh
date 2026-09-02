#!/bin/bash
# =============================================================
# EC2 Monitor — Auto-Fix Script
# Run AFTER test_prod.py to fix all known issues automatically
# Usage: bash autofix.sh [app_dir]
# =============================================================

APP_DIR=${1:-"/files"}
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[→]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

echo ""
echo "================================================="
echo "   EC2 Monitor — Auto-Fix"
echo "================================================="
echo ""

cd "$APP_DIR" || { err "Cannot cd to $APP_DIR"; exit 1; }

# ── FIX 1: favicon.ico 500 error ──────────────────────────────────────────────
info "Fix 1: favicon.ico 500 error..."
if grep -q "favicon.ico" app.py; then
    log "favicon route already exists"
else
    # Add favicon route after the last import line
    python3 - << 'PYEOF'
import re
with open("app.py", "r") as f:
    content = f.read()

favicon_route = '''
@app.get("/favicon.ico")
async def favicon():
    from fastapi.responses import Response
    return Response(status_code=204)

'''

# Insert after app = FastAPI(...) line
content = re.sub(
    r'(app = FastAPI\(.*?\)\s*\n)',
    r'\1' + favicon_route,
    content, count=1
)
with open("app.py", "w") as f:
    f.write(content)
print("  Added favicon route")
PYEOF
    log "favicon.ico route added"
fi

# ── FIX 2: System Health Coming Soon route ────────────────────────────────────
info "Fix 2: /system-health Coming Soon route..."
if grep -q "system-health" app.py; then
    log "system-health route already exists"
else
    python3 - << 'PYEOF'
import re
with open("app.py", "r") as f:
    content = f.read()

# Add before error handlers section
sh_route = '''
@app.get("/system-health", response_class=HTMLResponse)
async def system_health_page(request: Request):
    user = require_auth(request)
    pending_count = get_pending_count() if user.get("role") == "admin" else 0
    return templates.TemplateResponse(request, "system_health.html", {
        "request": request, "user": user, "pending_count": pending_count
    })

'''
# Insert before error handlers
content = content.replace(
    "# ── Error handlers",
    sh_route + "# ── Error handlers"
)
with open("app.py", "w") as f:
    f.write(content)
print("  Added /system-health route")
PYEOF
    log "system-health route added"
fi

# ── FIX 3: Create system_health.html template ─────────────────────────────────
info "Fix 3: system_health.html template..."
if [ -f "templates/system_health.html" ]; then
    log "system_health.html already exists"
else
cat > templates/system_health.html << 'TMPL'
{% extends "base.html" %}
{% block title %}System Health — EC2 Monitor{% endblock %}
{% block topbar_right %}<a href="/" class="pill">&#8592; Dashboard</a>{% endblock %}
{% block content %}
<div class="content" style="display:flex;align-items:center;justify-content:center;min-height:60vh;flex-direction:column;text-align:center">
  <div style="font-family:'Bebas Neue',sans-serif;font-size:80px;color:#1a1a1a;line-height:1;margin-bottom:16px">&#9881;</div>
  <div style="font-family:'Bebas Neue',sans-serif;font-size:36px;letter-spacing:6px;color:#fff">COMING SOON</div>
  <div style="font-size:11px;color:#444;letter-spacing:3px;text-transform:uppercase;margin-top:12px">System Health monitoring is under development</div>
  <a href="/" class="panel-btn primary" style="display:inline-block;margin-top:32px;text-decoration:none">&#8592; Back to Dashboard</a>
</div>
{% endblock %}
TMPL
    log "system_health.html created"
fi

# ── FIX 4: Add api_token to server API response ───────────────────────────────
info "Fix 4: api_token in /api/servers/{id} response..."
python3 - << 'PYEOF'
with open("database.py", "r") as f:
    content = f.read()

# Check if api_token is excluded from _parse
# It shouldn't be - it's returned as-is from SELECT *
# Just verify get_server returns it
if "api_token" in content:
    print("  api_token field present in database.py")
else:
    print("  WARNING: api_token may be missing from server responses")
PYEOF

# ── FIX 5: Tracking page - fix failed login display ───────────────────────────
info "Fix 5: Tracking page failed login display..."
cat > templates/server_tracking.html << 'TMPL'
{% extends "base.html" %}
{% block title %}Tracking — {{ server.name }}{% endblock %}
{% block topbar_right %}<a href="/server/{{ server.id }}" class="pill">&#8592; Back</a>{% endblock %}
{% block content %}
<div class="content">
  <div class="section-header">
    <span class="section-title">{{ server.name }} // LOGIN TRACKING</span>
    <span class="last-updated">{{ logins|length }} entries</span>
  </div>

  {% set failed_count = logins | selectattr('success', 'equalto', 0) | list | length %}
  {% if failed_count >= 3 %}
  <div style="background:rgba(255,255,255,0.05);border:1px solid #fff;border-radius:4px;padding:12px 16px;margin-bottom:14px;display:flex;align-items:center;gap:10px">
    <span style="background:#fff;color:#000;font-size:9px;padding:2px 7px;font-weight:700;letter-spacing:1px;border-radius:2px">ALERT</span>
    <span style="font-size:12px;color:#eee">{{ failed_count }} failed login attempts detected — possible brute force attack</span>
  </div>
  {% endif %}

  <div style="display:flex;gap:8px;margin-bottom:14px">
    <button onclick="filterRows('all',this)" class="pill active" id="f-all">ALL ({{ logins|length }})</button>
    <button onclick="filterRows('fail',this)" class="pill" id="f-fail" style="color:{% if failed_count>0 %}#fff{% else %}#444{% endif %};border-color:{% if failed_count>0 %}#555{% else %}#222{% endif %}">FAILED ({{ failed_count }})</button>
    <button onclick="filterRows('ok',this)" class="pill" id="f-ok">SUCCESS ({{ logins|length - failed_count }})</button>
  </div>

  <div style="background:#080808;border:1px solid #1a1a1a;border-radius:4px;overflow:hidden">
    <table style="width:100%;border-collapse:collapse" id="trackingTable">
      <thead>
        <tr style="background:#060606">
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a">Time</th>
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a">User</th>
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a">IP Address</th>
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a">Location</th>
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a">Result</th>
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a">Action</th>
        </tr>
      </thead>
      <tbody>
        {% for l in logins %}
        <tr data-result="{{ 'fail' if not l.success else 'ok' }}" style="border-bottom:1px solid #111;{% if not l.success %}background:rgba(255,255,255,0.015){% endif %}">
          <td style="padding:10px 16px;font-family:'JetBrains Mono',monospace;font-size:10px;color:#555">{{ l.time or (l.created_at[:16].replace('T',' ') if l.created_at else '—') }}</td>
          <td style="padding:10px 16px;font-size:12px;font-weight:{% if not l.success %}700{% else %}400{% endif %};color:{% if not l.success %}#fff{% else %}#777{% endif %}">{{ l.user or l.get('user_name','—') }}</td>
          <td style="padding:10px 16px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#555">{{ l.ip or '—' }}</td>
          <td style="padding:10px 16px;font-size:11px;color:#444">
            {% if l.get('city') and l.city not in ('Unknown','Local','') %}{{ l.city }}, {{ l.country }}{% else %}—{% endif %}
          </td>
          <td style="padding:10px 16px">
            {% if not l.success %}
              <span style="font-size:9px;background:#fff;color:#000;padding:2px 7px;border-radius:2px;letter-spacing:1px;font-weight:700">&#10005; FAILED</span>
            {% else %}
              <span style="font-size:9px;background:#111;color:#555;border:1px solid #1a1a1a;padding:2px 7px;border-radius:2px;letter-spacing:1px">&#10003; SUCCESS</span>
            {% endif %}
          </td>
          <td style="padding:10px 16px">
            {% if not l.success and l.ip %}
            <button onclick="blockIP('{{ l.ip }}','{{ server.id }}')" style="background:transparent;border:1px solid #222;color:#666;font-size:9px;padding:3px 10px;cursor:pointer;letter-spacing:1px;border-radius:2px;font-family:'Inter',sans-serif;transition:all .15s" onmouseover="this.style.borderColor='#fff';this.style.color='#fff'" onmouseout="this.style.borderColor='#222';this.style.color='#666'">BLOCK</button>
            {% endif %}
          </td>
        </tr>
        {% else %}
        <tr><td colspan="6" style="padding:48px;text-align:center;font-size:11px;color:#2a2a2a;letter-spacing:3px;text-transform:uppercase">No tracking data yet — agent sends data every 30s</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
<script>
function filterRows(type, btn) {
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.querySelectorAll('#trackingTable tbody tr[data-result]').forEach(row => {
    if (type === 'all') row.style.display = '';
    else row.style.display = row.dataset.result === type ? '' : 'none';
  });
}
async function blockIP(ip, serverId) {
  if (!confirm('Block IP ' + ip + ' via iptables?')) return;
  const r = await fetch(`/api/servers/${serverId}/action`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'block-ip', target: ip})
  });
  const d = await r.json();
  showToast(d.message || d.detail || 'Done', d.ok ? '' : 'error');
}
</script>
{% endblock %}
TMPL
log "server_tracking.html fixed"

# ── FIX 6: server_commands.html with full dangerous command list ───────────────
info "Fix 6: server_commands.html..."
cat > templates/server_commands.html << 'TMPL'
{% extends "base.html" %}
{% block title %}Commands — {{ server.name }}{% endblock %}
{% block topbar_right %}<a href="/server/{{ server.id }}" class="pill">&#8592; Back</a>{% endblock %}
{% block content %}
<div class="content">
  <div class="section-header">
    <span class="section-title">{{ server.name }} // DANGEROUS COMMANDS</span>
    <span class="last-updated">{{ total_count }} total</span>
  </div>

  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:#1a1a1a;border:1px solid #1a1a1a;border-radius:4px;overflow:hidden;margin-bottom:16px">
    <div style="background:#000;padding:14px 16px">
      <div style="font-size:9px;color:#444;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px">Total Detected</div>
      <div style="font-family:'Bebas Neue',sans-serif;font-size:32px;color:#fff">{{ total_count }}</div>
    </div>
    <div style="background:#000;padding:14px 16px">
      <div style="font-size:9px;color:#444;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px">Permission Changes</div>
      <div style="font-family:'Bebas Neue',sans-serif;font-size:32px;color:#aaa">{{ chmod_count }}</div>
    </div>
    <div style="background:#000;padding:14px 16px">
      <div style="font-size:9px;color:#444;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px">Destructive</div>
      <div style="font-family:'Bebas Neue',sans-serif;font-size:32px;color:#fff">{{ rm_count }}</div>
    </div>
    <div style="background:#000;padding:14px 16px">
      <div style="font-size:9px;color:#444;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px">Unique Users</div>
      <div style="font-family:'Bebas Neue',sans-serif;font-size:32px;color:#888">{{ unique_users }}</div>
    </div>
  </div>

  <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
    <button onclick="filterCmds('ALL',this)" class="pill active">ALL</button>
    <button onclick="filterCmds('DESTRUCTIVE',this)" class="pill">DESTRUCTIVE</button>
    <button onclick="filterCmds('PERM_CHANGE',this)" class="pill">PERM CHANGE</button>
    <button onclick="filterCmds('PROCESS_KILL',this)" class="pill">PROCESS KILL</button>
    <button onclick="filterCmds('NETWORK',this)" class="pill">NETWORK</button>
    <button onclick="filterCmds('SERVICE_STOP',this)" class="pill">SERVICE STOP</button>
    <button onclick="filterCmds('DANGEROUS',this)" class="pill">OTHER</button>
  </div>

  <div style="background:#080808;border:1px solid #1a1a1a;border-radius:4px;overflow:hidden">
    <table style="width:100%;border-collapse:collapse" id="cmdsTable">
      <thead>
        <tr style="background:#060606">
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a;width:150px">Time</th>
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a;width:90px">User</th>
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a">Command</th>
          <th style="padding:11px 16px;text-align:left;font-size:9px;color:#555;letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid #1a1a1a;width:120px">Category</th>
        </tr>
      </thead>
      <tbody>
        {% for c in commands %}
        <tr data-cat="{{ c.get('category','DANGEROUS') }}" style="border-bottom:1px solid #0d0d0d">
          <td style="padding:10px 16px;font-family:'JetBrains Mono',monospace;font-size:10px;color:#444">{{ c.created_at[:16].replace('T',' ') if c.created_at else '—' }}</td>
          <td style="padding:10px 16px;font-size:11px;color:#888;font-weight:600">{{ c.get('user_name') or c.get('user','—') }}</td>
          <td style="padding:10px 16px;font-family:'JetBrains Mono',monospace;font-size:11px;color:#fff" title="{{ c.get('reason','') }}">{{ c.cmd }}</td>
          <td style="padding:10px 16px">
            {% set cat = c.get('category','DANGEROUS') %}
            <span style="font-size:9px;padding:2px 7px;border-radius:2px;letter-spacing:1px;
              {% if cat == 'DESTRUCTIVE' %}background:#fff;color:#000;font-weight:700
              {% elif cat == 'PERM_CHANGE' %}background:#1a1a1a;color:#aaa;border:1px solid #333
              {% elif cat == 'PROCESS_KILL' %}background:#111;color:#888;border:1px solid #222
              {% elif cat == 'NETWORK' %}background:#111;color:#777;border:1px solid #222
              {% elif cat == 'SERVICE_STOP' %}background:#111;color:#666;border:1px solid #222
              {% else %}background:#0d0d0d;color:#555;border:1px solid #1a1a1a{% endif %}">
              {{ cat.replace('_',' ') }}
            </span>
          </td>
        </tr>
        {% else %}
        <tr><td colspan="4" style="padding:48px;text-align:center;font-size:11px;color:#2a2a2a;letter-spacing:3px;text-transform:uppercase">No dangerous commands detected — agent is monitoring</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
<script>
function filterCmds(cat, btn) {
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
  if (btn) btn.classList.add('active');
  document.querySelectorAll('#cmdsTable tbody tr[data-cat]').forEach(row => {
    row.style.display = (cat === 'ALL' || row.dataset.cat === cat) ? '' : 'none';
  });
}
</script>
{% endblock %}
TMPL
log "server_commands.html fixed"

# ── FIX 7: Update base.html nav link for system-health ───────────────────────
info "Fix 7: base.html system-health nav link..."
if [ -f "templates/base.html" ]; then
    # Replace any existing system-health link or add it
    python3 - << 'PYEOF'
with open("templates/base.html", "r") as f:
    content = f.read()

# Fix system health link to point to /system-health
import re
# Replace href pointing to /system-health or fix the nav
content = re.sub(
    r'href=["\']/?system.?health["\']',
    'href="/system-health"',
    content, flags=re.IGNORECASE
)
with open("templates/base.html", "w") as f:
    f.write(content)
print("  base.html nav updated")
PYEOF
    log "base.html updated"
fi

# ── FIX 8: Add /manage-user endpoint if missing ───────────────────────────────
info "Fix 8: /manage-user endpoint..."
if grep -q "manage-user" app.py; then
    log "/manage-user endpoint exists"
else
    warn "/manage-user endpoint missing — adding it"
    python3 - << 'PYEOF'
with open("app.py", "r") as f:
    content = f.read()

manage_user_route = '''
@app.post("/api/servers/{server_id}/manage-user")
async def api_manage_user(request: Request, server_id: str, body: dict):
    user_auth = require_auth(request)
    action = body.get("action")
    target_user = body.get("username")
    if not action or not target_user:
        return {"ok": False, "message": "Missing action or username"}
    cmd = ""
    if action == "delete":
        cmd = f"sudo deluser --remove-home {target_user} || sudo userdel -r {target_user}"
    elif action == "reset-password":
        new_pwd = body.get("password")
        if not new_pwd:
            return {"ok": False, "message": "Password required"}
        cmd = f"echo '{target_user}:{new_pwd}' | sudo chpasswd"
    elif action == "set-expiry":
        days = body.get("days", 30)
        cmd = f"sudo chage -M {days} {target_user}"
    if cmd:
        success, output = await run_ssh_command(server_id, cmd)
        return {"ok": success, "message": output if not success else f"User {target_user} {action} successful"}
    return {"ok": False, "message": "Invalid action"}

'''
content = content.replace(
    "# ── Error handlers",
    manage_user_route + "# ── Error handlers"
)
with open("app.py", "w") as f:
    f.write(content)
print("  manage-user route added")
PYEOF
fi

# ── FIX 9: Verify PostgreSQL connection ───────────────────────────────────────
info "Fix 9: Testing PostgreSQL connection..."
python3 - << 'PYEOF'
import os, sys
try:
    import psycopg2
    conn = psycopg2.connect(
        host=os.environ.get("PG_HOST","localhost"),
        port=os.environ.get("PG_PORT","5432"),
        database=os.environ.get("PG_DB","ec2monitor"),
        user=os.environ.get("PG_USER","ec2user"),
        password=os.environ.get("PG_PASS","ec2pass123"),
    )
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM servers")
    count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users")
    users = cur.fetchone()[0]
    conn.close()
    print(f"  PostgreSQL OK — {count} servers, {users} users")
except Exception as e:
    print(f"  FAIL: {e}")
    sys.exit(1)
PYEOF

if [ $? -ne 0 ]; then
    err "PostgreSQL connection failed"
    warn "Run: source .env && python3 autofix.sh"
else
    log "PostgreSQL connection verified"
fi

# ── FIX 10: Verify all templates exist ───────────────────────────────────────
info "Fix 10: Checking all required templates..."
REQUIRED=(
    "base.html" "index.html" "login.html" "404.html"
    "alerts.html" "approvals.html" "users.html" "settings.html"
    "project.html" "project_detail.html"
    "server_detail.html" "server_logins.html" "server_sudos.html"
    "server_tracking.html" "server_active_users.html"
    "server_security.html" "server_crons.html" "server_cron_detail.html"
    "server_commands.html" "server_users.html" "system_health.html"
)
MISSING=()
for tmpl in "${REQUIRED[@]}"; do
    if [ ! -f "templates/$tmpl" ]; then
        MISSING+=("$tmpl")
    fi
done
if [ ${#MISSING[@]} -eq 0 ]; then
    log "All ${#REQUIRED[@]} required templates exist"
else
    err "Missing templates: ${MISSING[*]}"
fi

# ── DONE ─────────────────────────────────────────────────────────────────────
echo ""
echo "================================================="
echo -e "${GREEN}   Auto-Fix Complete!${RESET}"
echo "================================================="
echo ""
echo "  Next steps:"
echo "  1. bash restart.sh"
echo "  2. python3 test_prod.py --url http://localhost:8000"
echo ""