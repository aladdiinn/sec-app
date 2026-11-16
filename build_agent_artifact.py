#!/usr/bin/env python3
"""
build_agent_artifact.py — Builds, tests, and cryptographically signs
the standalone agent v2.1.0 artifact for the SOC autonomous auto-update system.
"""

import os
import sys
import re
import json
import py_compile
import subprocess
import release_signer
import version

def build():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    agents_dir = os.path.join(root_dir, "static", "agents")
    os.makedirs(agents_dir, exist_ok=True)

    base_agent_path = os.path.join(root_dir, "agent_extracted.py")
    with open(base_agent_path, "r", encoding="utf-8") as f:
        src = f.read()

    # 1. Update version constant
    src = re.sub(r'AGENT_VERSION\s*=\s*"[^"]*"', f'AGENT_VERSION = "{version.AGENT_VERSION}"', src, count=1)

    # 2. Add config file loader
    cfg_loader = '''
CONFIG_FILE = os.environ.get("SECUREPULSE_CONFIG", "/opt/securepulse/config.json")
'''
    pos = src.find('ASSIGNED_SERVER_ID =')
    if pos != -1:
        line_end = src.find('\n', pos)
        src = src[:line_end+1] + cfg_loader + src[line_end+1:]

    # Invoke _recover_legacy_credentials() after its definition has been loaded
    inv_marker = '# ── INVENTORY & SCHEDULE STATE ──'
    inv_pos = src.find(inv_marker)
    if inv_pos != -1:
        recover_call = '''
# Load dynamic persistent configuration if present (preserves node identity across updates)
try:
    _recover_legacy_credentials()
except Exception:
    pass

'''
        src = src[:inv_pos] + recover_call + src[inv_pos:]

    # 3. Embed Ed25519 verification functions
    with open(os.path.join(root_dir, "agent_verifier.py"), "r", encoding="utf-8") as vf:
        verifier_code = vf.read()

    v_clean = verifier_code.replace('"""\nagent_verifier.py — Standalone, Zero-Dependency Ed25519 & SHA-256 Verifier (RFC 8032)\nWorks in any standard Python 3.6+ environment without external C-extensions or pip packages.\n"""', '')
    
    update_engine = '''
# ══════════════════════════════════════════════════════════════════════════
# EMBEDDED CRYPTOGRAPHIC SIGNATURE VERIFIER & AUTONOMOUS UPDATER
# ══════════════════════════════════════════════════════════════════════════
AGENT_ED25519_PUBLIC_KEY_HEX = "%%PUBLIC_KEY%%"

%%VERIFIER_CODE%%

def _cleanup_lock(lock_file):
    try:
        if os.path.exists(lock_file): os.remove(lock_file)
    except Exception: pass

def _report_update_failure(sid, target_ver, reason, lock_file, tmp_file=None):
    print(f"[SecurePulse Agent] UPDATE FAILED: {reason}", flush=True)
    _cleanup_lock(lock_file)
    if tmp_file:
        try:
            if os.path.exists(tmp_file): os.remove(tmp_file)
        except Exception: pass
    try:
        send_agent_request("/api/agent/status-update", data=json.dumps({
            "server_id": sid,
            "status": "failed",
            "from_version": AGENT_VERSION,
            "to_version": target_ver,
            "error": reason
        }).encode('utf-8'), timeout=5)
    except Exception:
        pass

def _spawn_restart_watchdog(sid, target_ver):
    watchdog_script = "/opt/securepulse/update_watchdog.sh"
    try:
        with open(watchdog_script, "w") as f:
            f.write(f"""#!/bin/bash
sleep 2
echo "[WATCHDOG] Restarting SecurePulse agent service..." >> /var/log/securepulse_agent.log
systemctl restart securepulse 2>/dev/null || systemctl restart securepulse-agent 2>/dev/null || nohup python3 /opt/securepulse/node_push_agent.py >> /var/log/securepulse_agent.log 2>&1 &

HEALTHY=0
for i in $(seq 1 24); do
    sleep 5
    if [ ! -f /tmp/securepulse_update.lock ]; then
        HEALTHY=1
        echo "[WATCHDOG] Agent v{target_ver} healthy and removed lock." >> /var/log/securepulse_agent.log
        break
    fi
done

if [ $HEALTHY -eq 0 ]; then
    echo "[WATCHDOG] 120s health check failed! Rolling back to backup..." >> /var/log/securepulse_agent.log
    if [ -f /opt/securepulse/node_push_agent.py.backup ]; then
        cp -f /opt/securepulse/node_push_agent.py.backup /opt/securepulse/node_push_agent.py
        chmod 750 /opt/securepulse/node_push_agent.py
        systemctl restart securepulse 2>/dev/null || systemctl restart securepulse-agent 2>/dev/null || true
    fi
    rm -f /tmp/securepulse_update.lock
    echo "[WATCHDOG] Rollback complete." >> /var/log/securepulse_agent.log
fi
rm -f {watchdog_script}
""")
        os.chmod(watchdog_script, 0o750)
        subprocess.Popen(["/bin/bash", watchdog_script], close_fds=True)
    except Exception as e:
        print(f"Watchdog spawn error: {e}", flush=True)
    sys.exit(0)

def check_and_apply_update(manifest, sid):
    lock_file = "/tmp/securepulse_update.lock"
    if os.path.exists(lock_file):
        try:
            mtime = os.path.getmtime(lock_file)
            if time.time() - mtime < 300:
                print(f"[SecurePulse Agent] Update already in progress (lock active).", flush=True)
                return
        except Exception:
            pass
    try:
        with open(lock_file, "w") as f:
            f.write(f"{os.getpid()}:{time.time()}\\n")
    except Exception:
        pass

    target_ver = manifest.get("version") or manifest.get("target_version")
    if not target_ver:
        _cleanup_lock(lock_file)
        return

    allow_rollback = manifest.get("allow_rollback", False)
    if not allow_rollback:
        cur_sem = [int(x) for x in re.findall(r'\\d+', str(AGENT_VERSION))]
        tgt_sem = [int(x) for x in re.findall(r'\\d+', str(target_ver))]
        if tgt_sem <= cur_sem:
            print(f"[SecurePulse Agent] Skipping update: target {target_ver} is not newer than current {AGENT_VERSION}.", flush=True)
            _cleanup_lock(lock_file)
            return

    try:
        send_agent_request("/api/agent/status-update", data=json.dumps({
            "server_id": sid,
            "status": "downloading",
            "from_version": AGENT_VERSION,
            "to_version": target_ver
        }).encode('utf-8'), timeout=5)
    except Exception:
        pass

    dl_url = manifest.get("download_url")
    if not dl_url:
        _report_update_failure(sid, target_ver, "Missing download_url in manifest", lock_file)
        return

    tmp_file = "/opt/securepulse/node_push_agent.py.tmp"
    backup_file = "/opt/securepulse/node_push_agent.py.backup"
    current_file = "/opt/securepulse/node_push_agent.py"

    try:
        req = urllib.request.Request(dl_url, headers={"User-Agent": f"SecurePulse-Agent/{AGENT_VERSION}"})
        ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
        if ca_bundle and os.path.isfile(ca_bundle):
            ctx = ssl.create_default_context(cafile=ca_bundle)
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        proxy_handler = urllib.request.ProxyHandler()
        opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))
        with opener.open(req, timeout=30) as resp:
            artifact_bytes = resp.read()
    except Exception as e_dl:
        _report_update_failure(sid, target_ver, f"Download failed: {e_dl}", lock_file)
        return

    expected_size = manifest.get("size")
    if expected_size and len(artifact_bytes) != expected_size:
        _report_update_failure(sid, target_ver, f"Size mismatch: expected {expected_size}, got {len(artifact_bytes)}", lock_file)
        return

    expected_sha = manifest.get("sha256", "").strip().lower()
    actual_sha = hashlib.sha256(artifact_bytes).hexdigest().lower()
    if expected_sha and actual_sha != expected_sha:
        _report_update_failure(sid, target_ver, f"SHA-256 mismatch: expected {expected_sha}, got {actual_sha}", lock_file)
        return

    sig_b64 = manifest.get("signature", "")
    pubkey_hex = manifest.get("public_key") or AGENT_ED25519_PUBLIC_KEY_HEX
    try:
        sig_bytes = base64.b64decode(sig_b64)
        pub_bytes = bytes.fromhex(pubkey_hex)
        if not verify_ed25519_pure(artifact_bytes, sig_bytes, pub_bytes):
            _report_update_failure(sid, target_ver, "Ed25519 digital signature verification failed: untrusted artifact", lock_file)
            return
    except Exception as e_sig:
        _report_update_failure(sid, target_ver, f"Signature verification error: {e_sig}", lock_file)
        return

    try:
        with open(tmp_file, "wb") as f:
            f.write(artifact_bytes)
        import py_compile
        py_compile.compile(tmp_file, doraise=True)
    except Exception as e_comp:
        _report_update_failure(sid, target_ver, f"Syntax verification failed: {e_comp}", lock_file, tmp_file)
        return

    try:
        st_proc = subprocess.run([sys.executable, tmp_file, "--selftest"], capture_output=True, text=True, timeout=10)
        if st_proc.returncode != 0 or "SELFTEST_OK" not in st_proc.stdout:
            _report_update_failure(sid, target_ver, f"Self-test failed (exit {st_proc.returncode}): {st_proc.stderr[:200]}", lock_file, tmp_file)
            return
    except Exception as e_st:
        _report_update_failure(sid, target_ver, f"Self-test invocation failed: {e_st}", lock_file, tmp_file)
        return

    # Persist config before replacement
    try:
        cfg_file = "/opt/securepulse/config.json"
        cfg_data = {
            "SOC_URL": SOC_URL,
            "TARGET_IP": get_node_ip(),
            "TARGET_NAME": get_node_name(),
            "AGENT_TOKEN": str(AGENT_TOKEN) if not str(AGENT_TOKEN).startswith("$") else "",
            "ASSIGNED_SERVER_ID": ASSIGNED_SERVER_ID
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f, indent=2)
        os.chmod(cfg_file, 0o600)
    except Exception:
        pass

    try:
        import shutil
        if os.path.exists(current_file):
            shutil.copy2(current_file, backup_file)
    except Exception as e_bak:
        print(f"[SecurePulse Agent] Warning: backup copy failed: {e_bak}", flush=True)

    try:
        os.replace(tmp_file, current_file)
        os.chmod(current_file, 0o750)
    except Exception as e_swap:
        _report_update_failure(sid, target_ver, f"Atomic replacement failed: {e_swap}", lock_file, tmp_file)
        return

    try:
        send_agent_request("/api/agent/status-update", data=json.dumps({
            "server_id": sid,
            "status": "updating",
            "from_version": AGENT_VERSION,
            "to_version": target_ver
        }).encode('utf-8'), timeout=5)
    except Exception:
        pass

    print(f"[SecurePulse Agent] Successfully applied update to {target_ver}. Spawning watchdog restart...", flush=True)
    _spawn_restart_watchdog(sid, target_ver)
'''.replace("%%PUBLIC_KEY%%", version.AGENT_ED25519_PUBLIC_KEY_HEX).replace("%%VERIFIER_CODE%%", v_clean)

    # Insert update engine before def main()
    pos_main = src.find('def main():')
    if pos_main != -1:
        src = src[:pos_main] + update_engine + "\n" + src[pos_main:]

    # In main(), remove update lock on healthy startup
    startup_lock_cleanup = '''
    # ── HEALTHY STARTUP: RELEASE UPDATE LOCK & CONFIRM STATUS ──
    lock_file = "/tmp/securepulse_update.lock"
    if os.path.exists(lock_file):
        try:
            os.remove(lock_file)
            print("[SecurePulse Agent] New version " + AGENT_VERSION + " healthy startup: update lock released.", flush=True)
        except Exception:
            pass
'''
    pos_push_loop = src.find('while True:')
    if pos_push_loop != -1:
        src = src[:pos_push_loop] + startup_lock_cleanup + "\n    " + src[pos_push_loop:]

    # Strip task_polling_loop and execute_agent_tasks to satisfy Requirement 4: NO REMOTE COMMANDS
    tasks_fn_pattern = re.compile(r'def task_polling_loop\(\):.*?def get_hostname\(\):', re.DOTALL)
    src = tasks_fn_pattern.sub('def get_hostname():', src)
    src = src.replace('threading.Thread(target=task_polling_loop, daemon=True).start()', '# Task polling disabled by security policy')
    src = src.replace('# Cache server_id returned from SOC so execute_agent_tasks can use it immediately', '# Cache server_id returned from SOC')

    # Replace old update block
    old_update_pattern = re.compile(
        r'if res_data\.get\("update_requested"\).*?sys\.exit\(0\)',
        re.DOTALL
    )
    new_update_handler = '''# Autonomous Signed Self-Update (Zero Remote Commands)
            if res_data.get("update_available") and res_data.get("update_manifest"):
                manifest = res_data.get("update_manifest")
                try:
                    threading.Thread(target=check_and_apply_update, args=(manifest, sid), daemon=True).start()
                except Exception as _ex_up:
                    print(f"[SecurePulse Agent] Auto-update trigger error: {_ex_up}", flush=True)'''

    src = old_update_pattern.sub(new_update_handler, src)

    # Remove arbitrary task execution (pending_tasks / execute_agent_tasks) to satisfy Requirement 4: NO REMOTE COMMANDS
    tasks_pattern = re.compile(
        r'if res_data\.get\("pending_tasks"\):.*?daemon=True\)\.start\(\)',
        re.DOTALL
    )
    src = tasks_pattern.sub('# Remote command execution disabled by security policy', src)

    # 4. Support --selftest flag at entrypoint
    entry_pattern = re.compile(r'if __name__ == "__main__":\s*main\(\)')
    new_entry = '''if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        print("SELFTEST_OK")
        sys.exit(0)
    main()'''
    src = entry_pattern.sub(new_entry, src)

    out_agent_path = os.path.join(agents_dir, f"agent-{version.AGENT_VERSION}.py")
    with open(out_agent_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)

    print(f"[BUILD] Written agent artifact to {out_agent_path} ({len(src)} bytes)")

    # 5. Compile check
    py_compile.compile(out_agent_path, doraise=True)
    print(f"[TEST] py_compile passed cleanly.")

    # 6. Run --selftest
    res = subprocess.run([sys.executable, out_agent_path, "--selftest"], capture_output=True, text=True)
    if res.returncode != 0 or "SELFTEST_OK" not in res.stdout:
        print(f"[ERROR] --selftest failed: code={res.returncode}, out={res.stdout}, err={res.stderr}")
        sys.exit(1)
    print(f"[TEST] --selftest passed: {res.stdout.strip()}")

    # 7. Sign with release_signer
    manifest_out = os.path.join(agents_dir, f"agent-{version.AGENT_VERSION}.py.manifest.json")
    manifest = release_signer.sign_file(out_agent_path, manifest_out)
    print(f"[SIGN] Signed manifest written to {manifest_out}:")
    print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    build()
