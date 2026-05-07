"""
models.py — All SQLAlchemy ORM models for SecurePulse.

Collections / Tables:
  users   — admin dashboard users
  servers — monitored servers (agents)
  events  — security events from agents
  alerts  — auto-generated security alerts
"""

from datetime import datetime, timezone
from database import db


class User(db.Model):
    __tablename__ = "users"

    id              = db.Column(db.Integer, primary_key=True)
    email           = db.Column(db.String(255), unique=True, nullable=False, index=True)
    hashed_password = db.Column(db.String(512), nullable=False)
    full_name       = db.Column(db.String(255), nullable=True)
    is_admin        = db.Column(db.Boolean, default=False, nullable=False)
    is_active       = db.Column(db.Boolean, default=True, nullable=False)
    created_at      = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return f"<User {self.email}>"


class Server(db.Model):
    __tablename__ = "servers"

    id            = db.Column(db.Integer, primary_key=True)
    hostname      = db.Column(db.String(255), nullable=False)
    ip_address    = db.Column(db.String(64), nullable=True)
    os_info       = db.Column(db.String(255), nullable=True)
    agent_token   = db.Column(db.String(512), unique=True, nullable=False, index=True)
    status        = db.Column(db.String(32), default="unknown")   # online|offline|unknown
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
    # event_type values: login | logout | cron_change | new_process |
    #                    process_ended | ssh_login | failed_login
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
    mitre_tactic = db.Column(db.String(128), nullable=True)
    mitre_technique = db.Column(db.String(128), nullable=True)
    score = db.Column(db.Integer, default=0, nullable=False)   # 0-100 CVSS-style risk score
    auto_promoted = db.Column(db.Boolean, default=False, nullable=False)
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

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action     = db.Column(db.String(255), nullable=False)
    target     = db.Column(db.String(255), nullable=True)
    timestamp  = db.Column(
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
    status      = db.Column(db.String(32), default="open")
    priority    = db.Column(db.String(16), default="medium")
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    summary     = db.Column(db.Text, nullable=True)
    due_at      = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at  = db.Column(db.DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))

class ThreatIndicator(db.Model):
    __tablename__ = "threat_indicators"
    id             = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(32), nullable=False)
    value          = db.Column(db.String(512), nullable=False, index=True)
    source         = db.Column(db.String(128))
    severity       = db.Column(db.String(16), default="medium")
    created_at     = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Playbook(db.Model):
    __tablename__ = "playbooks"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(255), nullable=False)
    actions     = db.Column(db.Text) # JSON string
    is_active   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

# Extend Alert to link to Case
Alert.case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)