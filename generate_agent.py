#!/usr/bin/env python3
"""
Standalone Agent Generator & Deployer
Extracts and configures the latest v1.7.0 BSMART SOC Node Agent directly from app.py
and deploys it to /opt/securepulse/node_push_agent.py with zero dependency on Docker or curl.
"""
import os, sys, re, subprocess

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    app_path = os.path.join(script_dir, "app.py")
    if not os.path.exists(app_path):
        print(f"[ERROR] Could not find app.py at {app_path}")
        sys.exit(1)

    with open(app_path, "r", encoding="utf-8") as f:
        text = f.read()

    s_marker = "cat << PY_EOF > /opt/securepulse/node_push_agent.py"
    start = text.find(s_marker)
    if start == -1:
        print("[ERROR] Could not find agent heredoc start marker in app.py")
        sys.exit(1)
    end = text.find("PY_EOF", start + len(s_marker))
    if end == -1:
        print("[ERROR] Could not find agent heredoc end marker in app.py")
        sys.exit(1)

    agent_code = text[start + len(s_marker) + 1:end].strip()

    # Unescape python template format braces {{ and }}
    agent_code = agent_code.replace("{{", "{").replace("}}", "}")

    # Substitute configuration variables for soc-server
    node_name = "soc-server"
    node_ip = "192.168.10.201"
    token = "sp-token-soc-server"
    assigned_id = "25"
    soc_url = "http://127.0.0.1:8001"

    # Query DB dynamically for the latest active server_id and token if possible
    try:
        p = subprocess.run([
            "docker", "exec", "-i", "bsmart-soc-db", "psql", "-U", "socadmin", "-d", "bsmart_soc", "-t", "-A", "-c",
            "SELECT id FROM servers WHERE LOWER(hostname) = 'soc-server' OR ip = '192.168.10.201' OR ip_address = '192.168.10.201' ORDER BY id DESC LIMIT 1;"
        ], capture_output=True, text=True, timeout=5)
        val = p.stdout.strip()
        if val.isdigit():
            assigned_id = val
            print(f"[INFO] Dynamically resolved Server ID from DB: {assigned_id}")
    except Exception:
        pass

    try:
        p = subprocess.run([
            "docker", "exec", "-i", "bsmart-soc-db", "psql", "-U", "socadmin", "-d", "bsmart_soc", "-t", "-A", "-c",
            f"SELECT COALESCE(agent_token, api_token, 'sp-token-soc-server') FROM servers WHERE id = {assigned_id} LIMIT 1;"
        ], capture_output=True, text=True, timeout=5)
        tok_val = p.stdout.strip()
        if tok_val and tok_val not in ("None", "null", ""):
            token = tok_val
            print(f"[INFO] Dynamically resolved Agent Token from DB: {token}")
    except Exception:
        pass

    agent_code = agent_code.replace('{base_url}', soc_url)
    agent_code = agent_code.replace('$NODE_IP', node_ip)
    agent_code = agent_code.replace('$NODE_NAME', node_name)
    agent_code = agent_code.replace('$TOKEN', token)
    agent_code = re.sub(r'int\("\$ASSIGNED_ID"\).*?\{server_id or "None"\}', assigned_id, agent_code)
    agent_code = agent_code.replace('$ASSIGNED_ID', assigned_id)
    agent_code = agent_code.replace('{server_id or "None"}', assigned_id)
    agent_code = agent_code.replace('{APP_BRAND}', 'BSMART SOC')

    # Ensure unbuffered output is at the very beginning
    unbuf_hdr = "import sys\ntry:\n    sys.stdout.reconfigure(line_buffering=True)\n    sys.stderr.reconfigure(line_buffering=True)\nexcept Exception:\n    pass\n"
    if "reconfigure(line_buffering=True)" not in agent_code:
        agent_code = unbuf_hdr + agent_code

    # Target destination
    dest_dir = "/opt/securepulse"
    dest_file = os.path.join(dest_dir, "node_push_agent.py")

    # If running locally or on server
    if os.name == 'posix':
        os.makedirs(dest_dir, exist_ok=True)
        with open(dest_file, "w", encoding="utf-8") as f:
            f.write(agent_code + "\n")
        os.chmod(dest_file, 0o755)
        print(f"[SUCCESS] Written {len(agent_code.splitlines())} lines to {dest_file} (Server ID: {assigned_id})")

        # Validate syntax
        p = subprocess.run([sys.executable, "-m", "py_compile", dest_file], capture_output=True, text=True)
        if p.returncode != 0:
            print(f"[ERROR] Syntax error in generated agent: {p.stderr}")
            sys.exit(1)
        print("[SUCCESS] Python syntax validation passed cleanly!")
    else:
        # In test / non-posix environment, save to local scratch file for verification
        test_out = os.path.join(script_dir, "test_generated_agent.py")
        with open(test_out, "w", encoding="utf-8") as f:
            f.write(agent_code + "\n")
        p = subprocess.run([sys.executable, "-m", "py_compile", test_out], capture_output=True, text=True)
        if p.returncode != 0:
            print(f"[ERROR] Syntax error: {p.stderr}")
            sys.exit(1)
        print(f"[SUCCESS] Standalone agent generated and verified ({len(agent_code.splitlines())} lines, Server ID: {assigned_id})")
        if os.path.exists(test_out):
            os.remove(test_out)

if __name__ == "__main__":
    main()
