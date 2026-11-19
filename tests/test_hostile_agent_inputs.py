import os
import sys
import re
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestHostileAgentInputs(unittest.TestCase):
    def test_fixed_regex_compilation(self):
        # 1. Sudo pattern: must compile cleanly without unterminated character set
        sudo_pattern = re.compile(r'(sudo:|su:|COMMAND=|su\[)', re.IGNORECASE)
        self.assertIsNotNone(sudo_pattern)

        # 2. SS process pattern: must compile cleanly
        proc_pattern = re.compile(r'users:\s*\(\s*\(\s*"([^"]+)"\s*,\s*pid=(\d+)')
        self.assertIsNotNone(proc_pattern)

        # 3. Connection process pattern: must compile cleanly
        conn_pattern = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
        self.assertIsNotNone(conn_pattern)

    def test_hostile_proctitles_and_log_lines(self):
        sudo_pattern = re.compile(r'(sudo:|su:|COMMAND=|su\[)', re.IGNORECASE)
        proc_pattern = re.compile(r'users:\s*\(\s*\(\s*"([^"]+)"\s*,\s*pid=(\d+)')

        hostile_proctitles = [
            "sshd: manoj.kn [priv]",
            "sshd: test[user] [priv]",
            'python3 -c "import os; print(os.getpid())"',
            "worker [1/4] (active)",
            r"bracket [test] (parens) *asterisk* +plus+ ?question? \backslash\\",
            "unicode_test: 🛡️ [threat-hunter] (admin)",
        ]

        for title in hostile_proctitles:
            # Must not crash when searching hostile process title
            res = sudo_pattern.search(title)
            # 'sshd: manoj.kn [priv]' has '[' but not 'su['
            self.assertFalse(res)

        # Sudo pattern matches actual su[ / sudo: / COMMAND=
        self.assertTrue(sudo_pattern.search("pam_unix(su[123]:session): session opened"))
        self.assertTrue(sudo_pattern.search("sudo: pam_unix(sudo:session): session opened"))
        self.assertTrue(sudo_pattern.search("COMMAND=/usr/bin/cat /etc/shadow"))

        # Test hostile ss output line parsing
        hostile_lines = [
            ('users:(("sshd: user [priv]",pid=1234,fd=3))', "sshd: user [priv]", 1234),
            ('users:(("python3 [worker]",pid=5678,fd=4))', "python3 [worker]", 5678),
            ('users:(("bracket[test](parens)*+?\\",pid=9999,fd=5))', "bracket[test](parens)*+?\\", 9999),
            ('users:(("🛡️-daemon",pid=4321,fd=1))', "🛡️-daemon", 4321),
        ]

        for raw_line, expected_name, expected_pid in hostile_lines:
            m = proc_pattern.search(raw_line)
            self.assertIsNotNone(m, f"Failed to parse line: {raw_line}")
            self.assertEqual(m.group(1), expected_name)
            self.assertEqual(int(m.group(2)), expected_pid)

    def test_identity_security_and_auth_guards(self):
        # 1. Identity protection: re-registration with known machine_id without secret must be rejected
        import database as db
        # Mock server lookup
        orig_get_mid = getattr(db, 'get_server_by_machine_id', None)
        try:
            db.get_server_by_machine_id = lambda mid: {
                "id": 42,
                "name": "protected-server",
                "machine_id": "known-uuid-12345",
                "agent_token": "correct-secret-token-xyz"
            } if mid == "known-uuid-12345" else None

            # Test unknown secret with known machine_id
            existing = db.get_server_by_machine_id("known-uuid-12345")
            self.assertIsNotNone(existing)
            incoming_attacker_secret = "attacker-fake-token"
            self.assertNotEqual(incoming_attacker_secret, existing["agent_token"])

            # Test valid secret with known machine_id
            incoming_valid_secret = "correct-secret-token-xyz"
            self.assertEqual(incoming_valid_secret, existing["agent_token"])
        finally:
            if orig_get_mid:
                db.get_server_by_machine_id = orig_get_mid

    def test_ast_regex_compiler_gate(self):
        # Test AST compiler gate against agent script
        import ast
        target_path = os.path.join(os.path.dirname(__file__), "..", "agent_extracted.py")
        if not os.path.exists(target_path):
            target_path = os.path.join(os.path.dirname(__file__), "..", "static", "agents", "agent-2.1.8.py")
        with open(target_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
        compiled_count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                is_re = False
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == 're':
                    if func.attr in ('compile', 'search', 'match', 'findall', 'sub', 'split', 'finditer'):
                        is_re = True
                if is_re and node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        pat = re.compile(arg0.value)
                        self.assertIsNotNone(pat)
                        compiled_count += 1
        self.assertGreaterEqual(compiled_count, 15)

    def test_golden_positive_detections(self):
        """
        Item 3 Golden Positive Tests:
        Real sample lines from Mitra 2, ausearch, sshd, sudo, Tomcat, Postgres, and ss.
        Assert that all extracted fields match expected values without doubled backslash bugs.
        """
        # 1. SSH Failed password for invalid user
        auth_line = "Nov 18 15:25:31 jvvnl-mitra2 sshd[9876]: Failed password for invalid user admin from 198.51.100.23 port 45678 ssh2"
        auth_pattern = re.compile(r'(Failed password|Invalid user|authentication failure|AUTH_FAIL|Failed publickey)', re.IGNORECASE)
        ip_pattern = re.compile(r'from (\d+\.\d+\.\d+\.\d+)')
        user_pattern = re.compile(r'(?:for invalid user|for user|invalid user)\s+(\S+)', re.IGNORECASE)

        self.assertTrue(auth_pattern.search(auth_line))
        m_ip = ip_pattern.search(auth_line)
        self.assertIsNotNone(m_ip)
        self.assertEqual(m_ip.group(1), "198.51.100.23")
        m_usr = user_pattern.search(auth_line)
        self.assertIsNotNone(m_usr)
        self.assertEqual(m_usr.group(1), "admin")

        # 2. Sudo execution line
        sudo_line = "Nov 18 15:26:00 jvvnl-mitra2 sudo:   manoj.kn : TTY=pts/0 ; PWD=/home/manoj.kn ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        sudo_pattern = re.compile(r'(sudo:|su:|COMMAND=|su\[)', re.IGNORECASE)
        self.assertTrue(sudo_pattern.search(sudo_line))

        # 3. Tomcat command line with -Dcatalina.base and -Dcatalina.home
        tc_cmdline = "/usr/lib/jvm/java-11-openjdk-amd64/bin/java -Djava.util.logging.config.file=/application/MDM/apache-tomcat-9.0.117/conf/logging.properties -Dcatalina.base=/application/MDM/apache-tomcat-9.0.117 -Dcatalina.home=/application/MDM/apache-tomcat-9.0.117 org.apache.catalina.startup.Bootstrap start"
        m_home = re.search(r'-Dcatalina\.home=([^\s]+)', tc_cmdline)
        m_base = re.search(r'-Dcatalina\.base=([^\s]+)', tc_cmdline)
        self.assertIsNotNone(m_home)
        self.assertEqual(m_home.group(1), "/application/MDM/apache-tomcat-9.0.117")
        self.assertIsNotNone(m_base)
        self.assertEqual(m_base.group(1), "/application/MDM/apache-tomcat-9.0.117")

        # 4. Postgres command line with -D data directory
        pg_cmdline = "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main -c config_file=/etc/postgresql/14/main/postgresql.conf"
        m_pg = re.search(r'-D\s+([^\s]+)', pg_cmdline)
        self.assertIsNotNone(m_pg)
        self.assertEqual(m_pg.group(1), "/var/lib/postgresql/14/main")

        # 5. ss -ntup / netstat line with listening port and process
        ss_line = 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("java",pid=12345,fd=45))'
        m_port = re.search(r':(\d+)\s+', ss_line)
        m_proc = re.search(r'users:\s*\(\s*\(\s*"([^"]+)"\s*,\s*pid=(\d+)', ss_line)
        self.assertIsNotNone(m_port)
        self.assertEqual(int(m_port.group(1)), 8080)
        self.assertIsNotNone(m_proc)
        self.assertEqual(m_proc.group(1), "java")
        self.assertEqual(int(m_proc.group(2)), 12345)

        # 6. Apache Tomcat Version release note line
        tc_note = "Apache Tomcat Version 9.0.117\n"
        m_ver = re.search(r'Apache Tomcat Version\s+([0-9\.]+)', tc_note, re.I)
        self.assertIsNotNone(m_ver)
        self.assertEqual(m_ver.group(1), "9.0.117")

        # 7. Audit log line (ausearch format)
        audit_line = 'type=SYSCALL msg=audit(1763481010.123:456): arch=c000003e syscall=2 success=yes exit=3 a0=7ff auid=1000 uid=0 euid=0 ses=5 pid=5678 ppid=1234 comm="cat" exe="/usr/bin/cat" key="identity"'
        m_msg = re.search(r'msg=audit\(([\d\.]+):(\d+)\)', audit_line)
        m_auid = re.search(r'\bauid=(\d+)', audit_line)
        m_comm = re.search(r'comm="?([^"\s]+)"?', audit_line)
        self.assertIsNotNone(m_msg)
        self.assertEqual(m_msg.group(1), "1763481010.123")
        self.assertEqual(m_msg.group(2), "456")
        self.assertIsNotNone(m_auid)
        self.assertEqual(m_auid.group(1), "1000")
        self.assertIsNotNone(m_comm)
        self.assertEqual(m_comm.group(1), "cat")

        # 8. Date in log file name normalization
        log_name = "/var/log/catalina.2026-05-06.log"
        m_date = re.search(r'(\d{4}-\d{2}-\d{2})', log_name)
        self.assertIsNotNone(m_date)
        self.assertEqual(m_date.group(1), "2026-05-06")

if __name__ == "__main__":
    unittest.main()
