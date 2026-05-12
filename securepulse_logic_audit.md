# SecurePulse: Deep Technical Logic Audit

This document identifies which features are **Real-World Functional** and which are **UI/Database Simulations**, along with their exact code locations.

---

## 1. Real-Time Functional Features (Actually Working)

| Feature | Working Mechanism | Code Location | Real-World Scenario |
| :--- | :--- | :--- | :--- |
| **Event Correlation** | Truly real-time. Ingests, checks rules, and alerts in one pass. | `app.py`: `ingest_event()` | Detecting an SSH login followed by a shadow file change. |
| **Rule Engine** | Matches YAML signatures against incoming data. | `app.py`: `RuleManager.evaluate()` | Flagging any command containing `nmap` or `netcat`. |
| **Threat Intel** | Live lookup against internal IOC database. | `app.py`: `ingest_event` (TI Section) | Blocking an IP that was added to the "Bad Actors" list 1 minute ago. |
| **UEBA (Anomaly)** | Hardcoded logic for time-based anomalies. | `app.py`: `ingest_event` (UEBA Section) | Flagging a login that occurs at 3:00 AM UTC. |
| **Collaboration** | Threaded comments and @mentions work in real-time. | `app.py`: `add_case_comment()` | Analysts discussing a case live within the investigation portal. |
| **D3.js Graph** | Dynamically maps alert relationships. | `investigation.html` (JS logic) | Visualizing the "Blast Radius" of a compromised server. |

---

## 2. UI/Database Simulated Features (Logical Only)

| Feature | Current Implementation | Code Location | Why it's "Simulation" |
| :--- | :--- | :--- | :--- |
| **Host Isolation** | Sets `status="isolated"` in DB. | `app.py`: `isolate_server()` | It does **not** push firewall rules to the host LAN. Attacker stays connected. |
| **Account Disable** | Logs a "SIMULATION" message. | `app.py`: `response_disable_account()` | It doesn't talk to Okta, AD, or LDAP. The user can still log in. |
| **Firewall Push** | Adds IP to `blocked_ips` table. | `app.py`: `response_block_ip()` | It doesn't connect to a physical firewall (Cisco/pfsense/AWS). Traffic isn't dropped. |
| **Ticket Sync** | Generates a fake `SEC-XXXX` ID. | `app.py`: `create_case_ticket()` | It doesn't call the Jira API to open a real ticket. |

---

## 3. Data Flow Architecture

### Real-Time Pipeline (Truly Functional)
1. **Agent** → `POST /api/events` (with JSON payload)
2. **Backend** → `RuleManager` checks YAML rules + `ThreatIndicator` table lookup.
3. **Database** → Stores `Event` and `Alert`.
4. **WebSocket** → `socketio.emit("new_event")` pushes data to browser.
5. **UI** → Dashboard updates without refresh.

### Simulation Pipeline (UI/DB Only)
1. **Analyst** → Clicks "Isolate Host" in UI.
2. **Backend** → `server.status` updated to `"isolated"`.
3. **Frontend** → UI shows "ISOLATED" badge and red banner.
4. **Missing Step** → No command sent to `Agent` or `Router` to actually cut traffic.

---

## 4. Code-Level Index

- **Main Logic Hub**: `app.py`
- **Database Models**: `models.py`
- **Detection Rules**: `rules/default_rules.yaml`
- **Investigation UI**: `templates/investigation.html`
- **Agent Registry**: `app.py`: `register_agent()`

---
*Audit completed by Antigravity SOC Analysis Engine*
