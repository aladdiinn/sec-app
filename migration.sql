-- SecurePulse SOC Database Migration Script
-- Execute on production PostgreSQL via:
-- psql -U securepulse -d securepulse_db -f migration.sql

-- 1. Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(16) DEFAULT 'warning',
    description TEXT,
    status VARCHAR(32) DEFAULT 'open',
    assigned_to VARCHAR(128),
    server_id INT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Detection Rules Table
CREATE TABLE IF NOT EXISTS detection_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(16) DEFAULT 'warning',
    enabled BOOLEAN DEFAULT TRUE,
    event_type VARCHAR(64) DEFAULT 'GENERAL',
    mitre_tactic VARCHAR(128),
    mitre_technique VARCHAR(128),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Threat Intelligence Table
CREATE TABLE IF NOT EXISTS threat_intel (
    id SERIAL PRIMARY KEY,
    ioc_value VARCHAR(512) NOT NULL,
    ioc_type VARCHAR(32) DEFAULT 'ipv4',
    severity VARCHAR(16) DEFAULT 'warning',
    description TEXT,
    source VARCHAR(128) DEFAULT 'Manual',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Playbooks Table
CREATE TABLE IF NOT EXISTS playbooks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    trigger_condition TEXT,
    actions JSONB DEFAULT '[]',
    steps TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Settings Table
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- 6. Reports Table
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    date_from DATE,
    date_to DATE,
    content JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Audit Log Table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    username VARCHAR(128),
    action VARCHAR(255) NOT NULL,
    target_type VARCHAR(64),
    target_id INT,
    detail TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Also ensure audit_logs alias table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INT,
    username VARCHAR(128),
    action VARCHAR(255) NOT NULL,
    target VARCHAR(255),
    target_type VARCHAR(64),
    target_id INT,
    detail TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Core Table Alterations
ALTER TABLE servers ADD COLUMN IF NOT EXISTS is_maintenance BOOLEAN DEFAULT FALSE;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS project_id INT;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS maintenance_until TIMESTAMP WITH TIME ZONE;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS case_id INT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(128);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(128);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS score INT DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS auto_promoted BOOLEAN DEFAULT FALSE;

ALTER TABLE projects ADD COLUMN IF NOT EXISTS server_ids TEXT DEFAULT '[]';

-- Seed default detection rules
INSERT INTO detection_rules (name, pattern, severity, enabled, event_type, mitre_tactic, mitre_technique)
VALUES
('Recursive Root Deletion', 'rm -rf /', 'critical', TRUE, 'DESTRUCTIVE', 'TA0040', 'T1485'),
('Fork Bomb DoS', ':(){:|:&};:', 'critical', TRUE, 'FORK_BOMB', 'TA0040', 'T1499'),
('Global Permission Modification', 'chmod 777', 'warning', TRUE, 'PERM_CHANGE', 'TA0005', 'T1222'),
('Shadow File Access', '/etc/shadow', 'critical', TRUE, 'CREDENTIAL_ACCESS', 'TA0006', 'T1003')
ON CONFLICT DO NOTHING;

-- Seed default threat intel IOCs
INSERT INTO threat_intel (ioc_value, ioc_type, severity, description, source)
VALUES
('185.220.101.42', 'ipv4', 'critical', 'Known Tor Exit Node & Scanner', 'AlienVault OTX'),
('45.142.195.12', 'ipv4', 'warning', 'SSH Brute-Force Botnet IP', 'AbuseIPDB'),
('malware-cnc-c2.top', 'domain', 'critical', 'Active Command & Control Server', 'ThreatConnect')
ON CONFLICT DO NOTHING;

-- Seed default playbooks
INSERT INTO playbooks (name, trigger_condition, steps, actions)
VALUES
('Auto Host Isolation on Ransomware', 'command contains rm -rf or alert contains DESTRUCTIVE', '1. Isolate host network\n2. Terminate malicious PID\n3. Notify SOC on Slack', '[{"type":"isolate_host"},{"type":"block_ip"},{"type":"notify_slack"}]'::jsonb),
('SSH Brute Force Auto-Mitigation', 'failed_count >= 5 or alert contains AUTH_FAIL', '1. Block IP on iptables\n2. Alert oncall engineer', '[{"type":"block_ip"},{"type":"notify_slack"}]'::jsonb),
('Service Recovery on Crash', 'status == offline or alert contains SERVICE_STOP', '1. Ping health check\n2. Restart service unit', '[{"type":"run_health_check"},{"type":"restart_service"}]'::jsonb)
ON CONFLICT DO NOTHING;

-- Seed default settings
INSERT INTO settings (key, value)
VALUES
('failed_logins_warning', '3'),
('failed_logins_critical', '10'),
('webhook_url', ''),
('webhook_type', 'slack')
ON CONFLICT DO NOTHING;
