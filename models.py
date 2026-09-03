"""
models.py — All SQLAlchemy ORM models for SecurePulse.

Collections / Tables:
  users              — admin dashboard users (with RBAC roles)
  servers            — monitored servers (agents)
  events             — security events from agents
  alerts             — auto-generated security alerts
  audit_logs         — immutable action log
  alert_rules        — detection rule configs
  cases              — incident investigation cases
  case_comments      — analyst collaboration comments (#34)
  notifications      — in-app notifications (#34)
  threat_indicators  — IOC threat intel
  playbooks          — automated response playbooks
  firewall_configs   — firewall integrations (#25)
  blocked_ips        — IP block records (#25)
  identity_providers — Okta/AD/LDAP config (#24/#32)
  jira_configs       — Jira/ServiceNow integration (#35)
  case_tickets       — linked external tickets (#35)
  projects           — endpoint grouping (Part C)
  project_endpoints  — project-endpoint mapping (Part C)
"""

from datetime import datetime, timezone
from database import db


# ─── RBAC Roles ───────────────────────────────────────────────────────────────
ROLE_SUPERUSER = "superuser"
ROLE_ADMIN     = "admin"
ROLE_NORMAL    = "normal"
VALID_ROLES    = {ROLE_SUPERUSER, ROLE_ADMIN, ROLE_NORMAL}


class User(db.Model):
    __tablename__ = "users"

    id              = db.Column(db.Integer, primary_key=True)
    email           = db.Column(db.String(255), unique=True, nullable=True, index=True)
    username        = db.Column(db.String(128), unique=True, nullable=True, index=True)
    hashed_password = db.Column(db.String(512), nullable=False)
    full_name       = db.Column(db.String(255), nullable=True)
    # RBAC: superuser | admin | normal  (replaces is_admin bool)
    role            = db.Column(db.String(32), default=ROLE_NORMAL, nullable=False)
    is_admin        = db.Column(db.Boolean, default=False, nullable=False)  # kept for backward compat
    is_active       = db.Column(db.Boolean, default=True, nullable=False)
    last_login      = db.Column(db.DateTime(timezone=True), nullable=True)
    mfa_enabled     = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret      = db.Column(db.String(64), nullable=True)  # TOTP secret (base32)
    created_at      = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    comments      = db.relationship("CaseComment", backref="author", lazy="dynamic",
                                    foreign_keys="CaseComment.user_id")
    notifications = db.relationship("Notification", backref="recipient", lazy="dynamic",
                                    foreign_keys="Notification.user_id")

    # Helper properties
    @property
    def is_superuser(self):
        return self.role == ROLE_SUPERUSER

    @property
    def is_admin_role(self):
        return self.role in (ROLE_SUPERUSER, ROLE_ADMIN)

    def can(self, permission):
        """Simple permission check based on role."""
        _perms = {
            "manage_users":      {ROLE_SUPERUSER},
            "modify_roles":      {ROLE_SUPERUSER},
            "system_health":     {ROLE_SUPERUSER},
            "sso_config":        {ROLE_SUPERUSER},
            "dr_test":           {ROLE_SUPERUSER},
            "isolate_host":      {ROLE_SUPERUSER, ROLE_ADMIN},
            "create_rules":      {ROLE_SUPERUSER, ROLE_ADMIN},
            "manage_playbooks":  {ROLE_SUPERUSER, ROLE_ADMIN},
            "manage_ioc":        {ROLE_SUPERUSER, ROLE_ADMIN},
            "block_ip":          {ROLE_SUPERUSER, ROLE_ADMIN},
            "disable_account":   {ROLE_SUPERUSER, ROLE_ADMIN},
            "generate_reports":  {ROLE_SUPERUSER, ROLE_ADMIN},
            "view_audit_log":    {ROLE_SUPERUSER, ROLE_ADMIN},
            "manage_projects":   {ROLE_SUPERUSER, ROLE_ADMIN},
            "view_dashboard":    {ROLE_SUPERUSER, ROLE_ADMIN, ROLE_NORMAL},
            "view_incidents":    {ROLE_SUPERUSER, ROLE_ADMIN, ROLE_NORMAL},
            "view_assets":       {ROLE_SUPERUSER, ROLE_ADMIN, ROLE_NORMAL},
            "view_reports":      {ROLE_SUPERUSER, ROLE_ADMIN, ROLE_NORMAL},
        }
        return self.role in _perms.get(permission, set())

    def __repr__(self):
        return f"<User {self.email} role={self.role}>"


class Server(db.Model):
    __tablename__ = "servers"

    id            = db.Column(db.Integer, primary_key=True)
    hostname      = db.Column(db.String(255), nullable=False)
    ip_address    = db.Column(db.String(64), nullable=True)
    os_info       = db.Column(db.String(255), nullable=True)
    agent_token   = db.Column(db.String(512), unique=True, nullable=False, index=True)
    status        = db.Column(db.String(32), default="unknown")   # online|offline|unknown|isolated
    
    # --- New Asset Tagging Fields ---
    role          = db.Column(db.String(32), default="none")      # primary | standby | none
    site          = db.Column(db.String(32), default="DC")        # DC | DR | Cloud
    cluster_id    = db.Column(db.String(128), nullable=True)      # To link DC/DR pairs
    is_maintenance  = db.Column(db.Boolean, default=False, nullable=False) # Maintenance suppression
    maintenance_until = db.Column(db.DateTime(timezone=True), nullable=True) # Automated window
    managed_services  = db.Column(db.Text, nullable=True) # JSON list of services {name, path, restart_cmd}
    
    last_seen     = db.Column(db.DateTime(timezone=True), nullable=True)
    registered_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    events = db.relationship("Event", backref="server", lazy="dynamic",
                             cascade="all, delete-orphan")
    alerts = db.relationship("Alert", backref="server", lazy="dynamic",
                             cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Server {self.hostname}>"


class Event(db.Model):
    __tablename__ = "events"

    id          = db.Column(db.Integer, primary_key=True)
    server_id   = db.Column(db.Integer, db.ForeignKey("servers.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    event_type  = db.Column(db.String(64), nullable=False, index=True)
    severity    = db.Column(db.String(16), default="info")  # info | warning | critical
    source      = db.Column(db.String(128), nullable=True)
    description = db.Column(db.Text, nullable=False)
    raw_data    = db.Column(db.Text, nullable=True)   # JSON string
    created_at  = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def __repr__(self):
        return f"<Event {self.event_type} server={self.server_id}>"


class Alert(db.Model):
    __tablename__ = "alerts"

    id          = db.Column(db.Integer, primary_key=True)
    server_id   = db.Column(db.Integer, db.ForeignKey("servers.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    event_id    = db.Column(db.Integer, db.ForeignKey("events.id", ondelete="SET NULL"),
                            nullable=True)
    alert_type  = db.Column(db.String(64), nullable=False)
    severity    = db.Column(db.String(16), default="warning")  # warning | critical
    title       = db.Column(db.String(255), nullable=False)
    message     = db.Column(db.Text, nullable=False)
    is_resolved = db.Column(db.Boolean, default=False, nullable=False)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    mitre_tactic    = db.Column(db.String(128), nullable=True)
    mitre_technique = db.Column(db.String(128), nullable=True)
    score       = db.Column(db.Integer, default=0, nullable=False)
    auto_promoted = db.Column(db.Boolean, default=False, nullable=False)
    case_id     = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)
    created_at  = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def __repr__(self):
        return f"<Alert {self.alert_type} server={self.server_id}>"


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action    = db.Column(db.String(255), nullable=False)
    target    = db.Column(db.String(255), nullable=True)
    details   = db.Column(db.Text, nullable=True)  # extra JSON context
    timestamp = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    user = db.relationship("User", backref="audit_logs")

    def __repr__(self):
        return f"<AuditLog {self.action} by user={self.user_id}>"


class AlertRule(db.Model):
    __tablename__ = "alert_rules"

    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(255), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    threshold  = db.Column(db.Integer, default=1)
    window     = db.Column(db.Integer, default=60)  # seconds
    severity   = db.Column(db.String(16), default="warning")
    playbook_id = db.Column(db.Integer, db.ForeignKey("playbooks.id"), nullable=True)
    is_active  = db.Column(db.Boolean, default=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return f"<AlertRule {self.name}>"


class Case(db.Model):
    __tablename__ = "cases"

    id          = db.Column(db.Integer, primary_key=True)
    title       = db.Column(db.String(255), nullable=False)
    status      = db.Column(db.String(32), default="open")  # open|in_progress|pending_review|resolved
    priority    = db.Column(db.String(16), default="medium")
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    summary     = db.Column(db.Text, nullable=True)
    due_at      = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at  = db.Column(db.DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))

    assignee = db.relationship("User", foreign_keys=[assignee_id], backref="assigned_cases")
    comments = db.relationship("CaseComment", backref="case", lazy="dynamic",
                               cascade="all, delete-orphan")
    ticket   = db.relationship("CaseTicket", backref="case", uselist=False,
                               cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Case #{self.id} {self.title}>"


# ─── Feature #34: Analyst Collaboration ───────────────────────────────────────

class CaseComment(db.Model):
    """Analyst comments/notes on a case. Immutable — cannot be deleted."""
    __tablename__ = "case_comments"

    id         = db.Column(db.Integer, primary_key=True)
    case_id    = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False)
    text       = db.Column(db.Text, nullable=False)
    is_system  = db.Column(db.Boolean, default=False, nullable=False)  # auto-generated system comments
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    def __repr__(self):
        return f"<CaseComment case={self.case_id} by user={self.user_id}>"


class Notification(db.Model):
    """In-app notifications: @mentions, assignments, SLA warnings, status changes."""
    __tablename__ = "notifications"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    type       = db.Column(db.String(32), nullable=False)  # mention|assign|sla|status
    message    = db.Column(db.String(512), nullable=False)
    case_id    = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"), nullable=True)
    is_read    = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return f"<Notification {self.type} user={self.user_id} read={self.is_read}>"


# ─── Feature #25: Firewall Rule Push ─────────────────────────────────────────

class FirewallConfig(db.Model):
    """Configured firewall integrations for IP blocking."""
    __tablename__ = "firewall_configs"

    id              = db.Column(db.Integer, primary_key=True)
    name            = db.Column(db.String(128), nullable=False)
    fw_type         = db.Column(db.String(32), nullable=False)  # paloalto|cisco|aws|pfsense|custom
    api_endpoint    = db.Column(db.String(512), nullable=True)
    credentials     = db.Column(db.Text, nullable=True)  # JSON (encrypted in production)
    default_ttl_hrs = db.Column(db.Integer, default=168)  # 7 days
    is_active       = db.Column(db.Boolean, default=True)
    created_at      = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<FirewallConfig {self.name} ({self.fw_type})>"


class BlockedIP(db.Model):
    """Record of IPs blocked via SecurePulse firewall push."""
    __tablename__ = "blocked_ips"

    id           = db.Column(db.Integer, primary_key=True)
    ip           = db.Column(db.String(64), nullable=False, index=True)
    reason       = db.Column(db.Text, nullable=False)
    blocked_by   = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    blocked_at   = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    ttl_hours    = db.Column(db.Integer, nullable=True)  # None = permanent
    expires_at   = db.Column(db.DateTime(timezone=True), nullable=True)
    firewalls    = db.Column(db.Text, nullable=True)  # JSON list of firewall config IDs
    status       = db.Column(db.String(32), default="active")  # active|expired|unblocked
    incident_id  = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)

    blocker = db.relationship("User", foreign_keys=[blocked_by])

    def __repr__(self):
        return f"<BlockedIP {self.ip} status={self.status}>"


# ─── Feature #24/#32: Identity Provider / SSO ────────────────────────────────

class IdentityProviderConfig(db.Model):
    """Okta / Azure AD / LDAP / Google Workspace configuration for SSO & account actions."""
    __tablename__ = "identity_provider_configs"

    id            = db.Column(db.Integer, primary_key=True)
    provider_type = db.Column(db.String(32), nullable=False)  # okta|azure_ad|ldap|google
    is_enabled    = db.Column(db.Boolean, default=False)
    config        = db.Column(db.Text, nullable=True)  # JSON: client_id, client_secret, tenant_id, etc.
    created_at    = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at    = db.Column(db.DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<IdentityProviderConfig {self.provider_type} enabled={self.is_enabled}>"


# ─── Feature #35: External Ticket Sync ───────────────────────────────────────

class JiraConfig(db.Model):
    """Jira / ServiceNow / Zendesk integration configuration."""
    __tablename__ = "jira_configs"

    id           = db.Column(db.Integer, primary_key=True)
    provider     = db.Column(db.String(32), default="jira_cloud")  # jira_cloud|jira_server|servicenow|zendesk
    base_url     = db.Column(db.String(512), nullable=True)
    project_key  = db.Column(db.String(64), nullable=True)
    api_token    = db.Column(db.String(512), nullable=True)
    user_email   = db.Column(db.String(255), nullable=True)
    issue_type   = db.Column(db.String(64), default="Bug")
    auto_create  = db.Column(db.String(32), default="critical")  # critical|critical_warning|all|off
    is_enabled   = db.Column(db.Boolean, default=False)
    status_map   = db.Column(db.Text, nullable=True)  # JSON mapping SP status -> Jira status
    created_at   = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<JiraConfig {self.provider} project={self.project_key}>"


class CaseTicket(db.Model):
    """External ticket linked to a SecurePulse case."""
    __tablename__ = "case_tickets"

    id            = db.Column(db.Integer, primary_key=True)
    case_id       = db.Column(db.Integer, db.ForeignKey("cases.id", ondelete="CASCADE"),
                              nullable=False, unique=True)
    ticket_id     = db.Column(db.String(64), nullable=False)  # e.g. SEC-2847
    ticket_url    = db.Column(db.String(512), nullable=True)
    ticket_status = db.Column(db.String(64), default="Open")
    provider      = db.Column(db.String(32), default="jira_cloud")
    last_synced   = db.Column(db.DateTime(timezone=True), nullable=True)
    sync_error    = db.Column(db.Text, nullable=True)
    created_at    = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<CaseTicket {self.ticket_id} case={self.case_id}>"


# ─── Feature #33: System Health ───────────────────────────────────────────────

class DRTestLog(db.Model):
    """Disaster Recovery test results log."""
    __tablename__ = "dr_test_logs"

    id          = db.Column(db.Integer, primary_key=True)
    run_by      = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    result      = db.Column(db.String(16), nullable=False)  # PASS | FAIL
    details     = db.Column(db.Text, nullable=True)
    rto_seconds = db.Column(db.Integer, nullable=True)
    ran_at      = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    runner = db.relationship("User", foreign_keys=[run_by])

    def __repr__(self):
        return f"<DRTestLog {self.result} at {self.ran_at}>"


# ─── Part C: Project Management ───────────────────────────────────────────────

class Project(db.Model):
    """A named group of monitored endpoints with a filtered dashboard."""
    __tablename__ = "projects"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_by  = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at  = db.Column(db.DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))

    creator   = db.relationship("User", foreign_keys=[created_by])
    endpoints = db.relationship("ProjectEndpoint", backref="project", lazy="dynamic",
                                cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Project #{self.id} {self.name}>"


class ProjectEndpoint(db.Model):
    """Many-to-many join between Projects and Servers."""
    __tablename__ = "project_endpoints"

    id         = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    server_id  = db.Column(db.Integer, db.ForeignKey("servers.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    added_by   = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    added_at   = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    server = db.relationship("Server", foreign_keys=[server_id])
    adder  = db.relationship("User", foreign_keys=[added_by])

    __table_args__ = (
        db.UniqueConstraint("project_id", "server_id", name="uq_project_server"),
    )

    def __repr__(self):
        return f"<ProjectEndpoint project={self.project_id} server={self.server_id}>"



# --- Threat Intelligence ---

class ThreatIndicator(db.Model):
    """Known malicious IPs, domains, or hashes."""
    __tablename__ = "threat_indicators"

    id             = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(32), default="ip")  # ip | domain | hash
    value          = db.Column(db.String(255), nullable=False, index=True)
    source         = db.Column(db.String(255), default="manual")
    severity       = db.Column(db.String(16), default="medium")
    is_blocked     = db.Column(db.Boolean, default=False)
    created_at     = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<ThreatIndicator {self.indicator_type}:{self.value}>"

# --- SOAR & Automation ---

class Playbook(db.Model):
    """Automated response workflows."""
    __tablename__ = "playbooks"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    actions     = db.Column(db.Text)  # JSON string
    is_active   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Playbook {self.name}>"


class NotificationRoute(db.Model):
    """Orchestrates where alerts are sent based on server tags (Site/Role)."""
    __tablename__ = "notification_routes"

    id              = db.Column(db.Integer, primary_key=True)
    match_type      = db.Column(db.String(32), nullable=False) # site | role | default
    match_value     = db.Column(db.String(128), nullable=True) # e.g. "Cloud", "standby"
    recipient_email = db.Column(db.String(255), nullable=False)
    is_active       = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<NotificationRoute {self.match_type}:{self.match_value} -> {self.recipient_email}>"
