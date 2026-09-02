from typing import List, Dict

# Basic Sigma-like rule definitions
RULES = [
    {
        "id": "failed_login_brute_force",
        "title": "Brute Force Attempt Detected",
        "description": "Multiple failed logins from the same source in a short window.",
        "severity": "high",
        "mitre_id": "T1110",
        "condition": lambda event, history: event.get("type") == "failed_login" and len([e for e in history if e.get("type") == "failed_login" and e.get("raw_data", {}).get("ip") == event.get("raw_data", {}).get("ip")]) > 5
    },
    {
        "id": "web_shell_detection",
        "title": "Suspicious Process Spawned from Web Server",
        "description": "Interactive shell (bash/sh) spawned by a web server process (www-data/nginx).",
        "severity": "critical",
        "mitre_id": "T1505.003",
        "condition": lambda event, history: event.get("type") == "new_process" and \
                                         event.get("raw_data", {}).get("user") in ["www-data", "nginx", "apache"] and \
                                         event.get("raw_data", {}).get("exe") in ["/bin/bash", "/bin/sh", "bash", "sh"]
    },
    {
        "id": "privilege_escalation_sudo",
        "title": "Suspicious Sudo Execution",
        "description": "Sudo used to run a sensitive utility (chmod, chown, shadow) by a non-admin.",
        "severity": "high",
        "mitre_id": "T1548.003",
        "condition": lambda event, history: event.get("type") == "command" and \
                                         "sudo" in event.get("description", "") and \
                                         any(cmd in event.get("description", "") for cmd in ["chmod 777", "/etc/shadow", "passwd"])
    },
    {
        "id": "credential_dumping_attempt",
        "title": "Potential Credential Dumping",
        "description": "Access to /etc/shadow or use of tools like mimikatz/grep on sensitive files.",
        "severity": "critical",
        "mitre_id": "T1003",
        "condition": lambda event, history: "/etc/shadow" in event.get("description", "") or \
                                         "grep -i pass" in event.get("description", "")
    }
]

def check_rules(event_data: Dict, event_history: List[Dict] = []) -> List[Dict]:
    triggered = []
    for rule in RULES:
        try:
            if rule["condition"](event_data, event_history):
                triggered.append(rule)
        except Exception as e:
            continue
    return triggered
