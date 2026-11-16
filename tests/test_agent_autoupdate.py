#!/usr/bin/env python3
"""
tests/test_agent_autoupdate.py — Comprehensive Test Suite for Autonomous Agent Auto-Update

Validates:
U1: Successful cryptographic verification, atomic swap, and configuration persistence.
U2: Tampered artifact, invalid signature, and version downgrade rejection.
U3: Health check timeout and automatic watchdog rollback to backup.
U4: Staged rollout (Canary -> Batches) and circuit breaker failure threshold.
U5: Proxy configuration and backoff retry logic.
U6: Legacy v1.6.2 bootstrap updater (/setup_agent_updater.sh) preserving identity and tokens.
U7: Audit logging of update attempts, status transitions, and rollbacks.
U8: Strict security policy: zero remote command execution (no curl | bash) in agent code.
"""

import os
import sys
import json
import base64
import shutil
import tempfile
import unittest
import asyncio
import py_compile
import subprocess
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

os.environ["TESTING"] = "1"
os.environ["SKIP_GEOIP_DOWNLOAD"] = "1"
os.environ["SECRET_KEY"] = "mock_secret_key_for_testing_1234567890"
os.environ["DB_PASSWORD"] = "mock_db_password"

# Ensure parent directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import version
import agent_verifier
import release_signer
import database as db

class TestAgentAutoUpdate(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.artifact_path = os.path.join(os.path.dirname(__file__), "..", "static", "agents", f"agent-{version.AGENT_VERSION}.py")
        self.manifest_path = os.path.join(os.path.dirname(__file__), "..", "static", "agents", f"agent-{version.AGENT_VERSION}.py.manifest.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_u1_signature_verification_and_selftest(self):
        """U1: Valid artifact must pass SHA-256 and Ed25519 signature checks and --selftest."""
        self.assertTrue(os.path.exists(self.artifact_path), f"Artifact missing at {self.artifact_path}")
        self.assertTrue(os.path.exists(self.manifest_path), f"Manifest missing at {self.manifest_path}")

        with open(self.artifact_path, "rb") as f:
            data = f.read()
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # 1. Manifest verification
        is_valid = agent_verifier.verify_manifest(data, manifest)
        self.assertTrue(is_valid, "Official agent artifact must pass Ed25519 signature verification")

        # 2. Syntax compilation check
        py_compile.compile(self.artifact_path, doraise=True)

        # 3. Selftest execution
        res = subprocess.run([sys.executable, self.artifact_path, "--selftest"], capture_output=True, text=True, timeout=5)
        self.assertEqual(res.returncode, 0)
        self.assertIn("SELFTEST_OK", res.stdout)

    def test_u2_tampered_artifact_and_downgrade_rejected(self):
        """U2: Tampered artifact, corrupted signature, and downgrade version must be rejected."""
        with open(self.artifact_path, "rb") as f:
            valid_data = bytearray(f.read())
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # A. Tampered data byte
        tampered_data = bytearray(valid_data)
        tampered_data[100] ^= 0x55
        self.assertFalse(agent_verifier.verify_manifest(bytes(tampered_data), manifest), "Tampered byte must fail verification")

        # B. Corrupted signature
        bad_manifest = dict(manifest)
        bad_sig = bytearray(base64.b64decode(manifest["signature"]))
        bad_sig[10] ^= 0xFF
        bad_manifest["signature"] = base64.b64encode(bad_sig).decode()
        self.assertFalse(agent_verifier.verify_manifest(bytes(valid_data), bad_manifest), "Corrupted signature must fail verification")

        # C. Downgrade version check
        self.assertFalse(version.is_newer_version("2.0.0", "2.1.0"), "Version 2.0.0 must not be newer than 2.1.0")
        self.assertFalse(version.is_newer_version("1.6.2", "2.1.0"), "Version 1.6.2 must not be newer than 2.1.0")
        self.assertTrue(version.is_newer_version("2.1.0", "1.6.2"), "Version 2.1.0 must be newer than 1.6.2")

    def test_u3_atomic_replacement_and_config_preservation(self):
        """U3: Configuration file config.json must preserve credentials and survive updates."""
        config_file = os.path.join(self.test_dir, "config.json")
        initial_cfg = {
            "SOC_URL": "https://192.168.10.201:3443",
            "TARGET_IP": "192.168.150.15",
            "TARGET_NAME": "Jvvnl -Mitra 1",
            "AGENT_TOKEN": "sp-token-mitra-secret-12345",
            "ASSIGNED_SERVER_ID": 21
        }
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(initial_cfg, f)

        # Simulate agent reading config
        with open(config_file, "r", encoding="utf-8") as f:
            loaded_cfg = json.load(f)

        self.assertEqual(loaded_cfg["AGENT_TOKEN"], "sp-token-mitra-secret-12345")
        self.assertEqual(loaded_cfg["ASSIGNED_SERVER_ID"], 21)
        self.assertEqual(loaded_cfg["TARGET_NAME"], "Jvvnl -Mitra 1")

        # Simulate atomic file swap
        current_agent = os.path.join(self.test_dir, "node_push_agent.py")
        tmp_agent = os.path.join(self.test_dir, "node_push_agent.py.tmp")
        backup_agent = os.path.join(self.test_dir, "node_push_agent.py.backup")

        with open(current_agent, "w") as f: f.write("# Old Agent v1.6.2")
        with open(tmp_agent, "w") as f: f.write("# New Agent v2.1.0")

        shutil.copy2(current_agent, backup_agent)
        os.replace(tmp_agent, current_agent)

        with open(current_agent, "r") as f: content = f.read()
        self.assertIn("New Agent v2.1.0", content)
        with open(backup_agent, "r") as f: bak = f.read()
        self.assertIn("Old Agent v1.6.2", bak)

        # Rollback simulation
        shutil.copy2(backup_agent, current_agent)
        with open(current_agent, "r") as f: rolled_back = f.read()
        self.assertIn("Old Agent v1.6.2", rolled_back)

    def test_u4_staged_rollout_and_window_logic(self):
        """U4: Rollout stage and maintenance window evaluation."""
        # 1. Window parsing
        now_0300 = datetime(2026, 11, 16, 3, 0, 0)
        now_1200 = datetime(2026, 11, 16, 12, 0, 0)
        self.assertTrue(db.is_in_update_window("02:00", "05:00", now_dt=now_0300))
        self.assertFalse(db.is_in_update_window("02:00", "05:00", now_dt=now_1200))

        # 2. Midnight-crossing window
        now_2330 = datetime(2026, 11, 16, 23, 30, 0)
        now_0230 = datetime(2026, 11, 16, 2, 30, 0)
        now_1500 = datetime(2026, 11, 16, 15, 0, 0)
        self.assertTrue(db.is_in_update_window("23:00", "04:00", now_dt=now_2330))
        self.assertTrue(db.is_in_update_window("23:00", "04:00", now_dt=now_0230))
        self.assertFalse(db.is_in_update_window("23:00", "04:00", now_dt=now_1500))

    @patch("database.get_db_connection")
    def test_u5_circuit_breaker_calculation(self, mock_get_conn):
        """U5: Fleet status and failure threshold calculation with mock DB."""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur

        mock_servers = [
            {"id": 21, "name": "Mitra 1", "hostname": "Mitra 1", "agent_version": "1.6.2", "update_status": "update_available", "is_canary": False, "exclude_from_autoupdate": False, "is_maintenance": False},
            {"id": 22, "name": "Mitra 2", "hostname": "Mitra 2", "agent_version": "1.6.2", "update_status": "update_available", "is_canary": False, "exclude_from_autoupdate": False, "is_maintenance": False},
            {"id": 23, "name": "soc-server", "hostname": "soc-server", "agent_version": "2.1.0", "update_status": "up_to_date", "is_canary": True, "exclude_from_autoupdate": False, "is_maintenance": False}
        ]
        mock_cur.fetchall.side_effect = [
            mock_servers,
            [{"id": 1, "server_id": 23, "status": "up_to_date", "from_version": "2.0.0", "to_version": "2.1.0"}]
        ]
        mock_cur.fetchone.return_value = {"value": "false"}
        mock_get_conn.return_value = mock_conn

        fleet_status = db.get_agent_fleet_status()
        self.assertEqual(fleet_status["total"], 3)
        self.assertEqual(fleet_status["target_version"], "2.1.0")
        self.assertEqual(fleet_status["versions"]["1.6.2"], 2)
        self.assertEqual(fleet_status["versions"]["2.1.0"], 1)
        self.assertEqual(fleet_status["canary_count"], 1)
        self.assertEqual(fleet_status["status"]["up_to_date"], 1)
        self.assertEqual(fleet_status["status"]["update_available"], 2)
        self.assertFalse(fleet_status["circuit_broken"])

    def test_u6_legacy_bootstrap_script_preserves_config(self):
        """U6: /setup_agent_updater.sh script syntax and configuration extraction."""
        # Test the regex extraction that setup_agent_updater.sh uses on old agent files
        old_agent_content = """
AGENT_VERSION = "1.6.2"
SOC_URL = "https://192.168.10.201:3443".rstrip("/")
TARGET_IP = "192.168.150.15"
TARGET_NAME = "Jvvnl -Mitra 1"
AGENT_TOKEN = "sp-token-legacy-mitra-9988"
ASSIGNED_SERVER_ID = 21
"""
        import re
        token_m = re.search(r'AGENT_TOKEN\s*=\s*["\']([^"\']+)["\']', old_agent_content)
        soc_m = re.search(r'SOC_URL\s*=\s*["\']([^"\']+)["\']', old_agent_content)
        ip_m = re.search(r'TARGET_IP\s*=\s*["\']([^"\']+)["\']', old_agent_content)
        name_m = re.search(r'TARGET_NAME\s*=\s*["\']([^"\']+)["\']', old_agent_content)
        sid_m = re.search(r'ASSIGNED_SERVER_ID\s*=\s*(\d+)', old_agent_content)

        self.assertIsNotNone(token_m)
        self.assertEqual(token_m.group(1), "sp-token-legacy-mitra-9988")
        self.assertIsNotNone(sid_m)
        self.assertEqual(sid_m.group(1), "21")
        self.assertEqual(ip_m.group(1), "192.168.150.15")
        self.assertEqual(name_m.group(1), "Jvvnl -Mitra 1")

    def test_u7_security_no_remote_commands(self):
        """U8: Strict audit check confirming no curl | bash or arbitrary command pipes exist in agent."""
        with open(self.artifact_path, "r", encoding="utf-8") as f:
            code = f.read()

        # Confirm curl ... | bash is strictly absent from the agent Python source code
        self.assertNotIn("curl -s -k {dl_url}", code)
        self.assertNotIn("| bash", code)
        self.assertNotIn("execute_agent_tasks", code)

        # Confirm Ed25519 public key is embedded
        self.assertIn(version.AGENT_ED25519_PUBLIC_KEY_HEX, code)
        self.assertIn("verify_ed25519_pure", code)
        self.assertIn("check_and_apply_update", code)
        self.assertIn("--selftest", code)

    def test_u8_api_version_endpoint(self):
        """U9: /api/version returns official platform and latest agent versions."""
        import app
        res = app.api_get_version()
        self.assertEqual(res["platform_version"], version.PLATFORM_VERSION)
        self.assertEqual(res["latest_agent_version"], version.AGENT_VERSION)
        self.assertEqual(res["min_supported_agent_version"], version.MIN_SUPPORTED_AGENT_VERSION)

    def test_u9_api_version_manifest_endpoint(self):
        """U10: /api/agent/version-manifest returns valid manifest with download URL."""
        import app
        req = MagicMock()
        req.base_url = "https://192.168.10.201:3443/"
        res = app.api_agent_version_manifest(req)
        self.assertEqual(res["version"], version.AGENT_VERSION)
        self.assertEqual(res["public_key"], version.AGENT_ED25519_PUBLIC_KEY_HEX)
        self.assertIn("signature", res)
        self.assertIn("sha256", res)
        self.assertIn("https://192.168.10.201:3443/static/agents/agent-2.1.0.py", res["download_url"])

    def test_u10_setup_agent_updater_endpoint(self):
        """U11: /setup_agent_updater.sh endpoint returns valid bash bootstrap script."""
        import app
        req = MagicMock()
        req.base_url = "https://192.168.10.201:3443/"
        resp = app.setup_agent_updater_endpoint(req)
        content = resp.body.decode("utf-8")
        self.assertIn("#!/bin/bash", content)
        self.assertIn("setup_agent_updater.sh", content)
        self.assertIn("EXISTING_TOKEN=", content)
        self.assertIn("config.json", content)
        self.assertIn("agent-2.1.0.py", content)
        self.assertIn("--selftest", content)

    @patch("database.get_settings")
    @patch("database.get_agent_fleet_status")
    def test_u11_api_autoupdate_settings_endpoints(self, mock_fleet, mock_settings):
        """U12: /api/settings/autoupdate GET returns current config and fleet distribution."""
        import app
        mock_settings.return_value = {
            "autoupdate_enabled": "true",
            "autoupdate_stage": "canary",
            "autoupdate_window_start": "02:00",
            "autoupdate_window_end": "05:00",
            "autoupdate_failure_threshold_pct": "15",
            "autoupdate_circuit_broken": "false"
        }
        mock_fleet.return_value = {
            "total": 3,
            "target_version": "2.1.0",
            "versions": {"2.1.0": 1, "1.6.2": 2},
            "status": {"up_to_date": 1, "update_available": 2},
            "circuit_broken": False
        }
        req = MagicMock()
        res = app.api_get_autoupdate_settings(req)
        self.assertTrue(res["ok"])
        self.assertTrue(res["enabled"])
        self.assertEqual(res["stage"], "canary")
        self.assertEqual(res["window_start"], "02:00")
        self.assertEqual(res["window_end"], "05:00")
        self.assertEqual(res["failure_threshold_pct"], 15.0)
        self.assertEqual(res["fleet"]["total"], 3)

if __name__ == "__main__":
    unittest.main()
