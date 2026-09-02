-- SOC Platform Database Schema (PostgreSQL)
-- Version: 1.0.0

-- 1. RBAC & User Management
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(512) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- 2. Asset Management
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    os_type VARCHAR(64), -- linux, windows, macos
    os_version VARCHAR(128),
    criticality VARCHAR(16) DEFAULT 'medium', -- low, medium, high, mission_critical
    agent_version VARCHAR(32),
    last_seen TIMESTAMP WITH TIME ZONE,
    status VARCHAR(32) DEFAULT 'unknown',
    tags JSONB, -- For custom groupings
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Threat Intelligence (IOCs)
CREATE TABLE IF NOT EXISTS iocs (
    id SERIAL PRIMARY KEY,
    type VARCHAR(32) NOT NULL, -- ipv4, domain, file_hash, url
    value TEXT NOT NULL,
    source VARCHAR(128),
    confidence INTEGER DEFAULT 50,
    severity VARCHAR(16) DEFAULT 'medium',
    description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

-- 4. Incident Management
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    status VARCHAR(32) DEFAULT 'open', -- open, in_progress, resolved, closed
    priority VARCHAR(16) DEFAULT 'medium', -- low, medium, high, critical
    severity_score INTEGER DEFAULT 0, -- Calculated CVSS or custom
    assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    summary TEXT,
    mitre_techniques JSONB, -- Array of TIDs
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    type VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(16) DEFAULT 'warning',
    raw_event_data JSONB,
    source VARCHAR(128), -- EDR, Firewall, IDS
    is_resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Logging & Audit
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) DEFAULT 'info',
    description TEXT,
    raw_data JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    target_table VARCHAR(64),
    target_id INTEGER,
    details JSONB,
    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. SOAR / Automation
CREATE TABLE IF NOT EXISTS playbooks (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    trigger_type VARCHAR(64) NOT NULL,
    definition JSONB NOT NULL, -- Step definitions
    is_active BOOLEAN DEFAULT TRUE,
    created_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    id SERIAL PRIMARY KEY,
    playbook_id INTEGER REFERENCES playbooks(id),
    incident_id INTEGER REFERENCES incidents(id),
    status VARCHAR(32) DEFAULT 'running',
    results JSONB,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. Performance Indexing
CREATE INDEX idx_alerts_incident_id ON alerts(incident_id);
CREATE INDEX idx_alerts_asset_id ON alerts(asset_id);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_security_events_asset_id ON security_events(asset_id);
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_iocs_value ON iocs(value);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_ip ON assets(ip_address);

-- 8. Sample Data
INSERT INTO roles (name, description) VALUES 
('Admin', 'Full system access'),
('Analyst', 'Investigate and resolve incidents'),
('Viewer', 'Read-only access');

INSERT INTO assets (hostname, ip_address, os_type, criticality, status) VALUES
('PROD-WEB-01', '10.0.1.10', 'linux', 'high', 'online'),
('PROD-DB-01', '10.0.1.20', 'linux', 'mission_critical', 'online'),
('CORP-LAPTOP-05', '192.168.1.55', 'windows', 'low', 'offline');

INSERT INTO iocs (type, value, source, severity, description) VALUES
('ipv4', '185.220.101.42', 'AlienVault', 'high', 'Known Tor Exit Node'),
('file_hash', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Internal', 'critical', 'Ransomware Variant A');

INSERT INTO playbooks (name, trigger_type, definition) VALUES
('Auto-Isolate Host', 'alert_severity_critical', '{"steps": [{"action": "isolate_agent"}, {"action": "notify_slack"}]}');
