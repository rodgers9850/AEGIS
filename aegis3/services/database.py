"""Identity registry and per-tenant SQLite database routing."""

import os
import re
import hmac
import hashlib
import sqlite3
import uuid
from datetime import datetime

from services.core import hash_password


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDENTITY_DB = os.environ.get("AEGIS_IDENTITY_DB_PATH", os.path.join(ROOT_DIR, "identity.db"))
DEFAULT_TENANT_ID = "tenant-acme-001"
_TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def now_iso():
    return datetime.utcnow().isoformat() + "Z"


def get_identity_db():
    os.makedirs(os.path.dirname(os.path.abspath(IDENTITY_DB)), exist_ok=True)
    db = sqlite3.connect(IDENTITY_DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_identity():
    db = get_identity_db()
    try:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS principals (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id),
            email TEXT NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT,
            UNIQUE (tenant_id, email)
        );
        CREATE INDEX IF NOT EXISTS idx_principals_email ON principals(email);
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            token_id TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL REFERENCES tenants(id),
            hostname TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_seen TEXT
        );
        """)
        db.execute(
            "INSERT OR IGNORE INTO tenants (id,name,created_at) VALUES (?,?,?)",
            (DEFAULT_TENANT_ID, "Acme Corp", now_iso()),
        )
        email = os.environ.get("AEGIS_ADMIN_EMAIL", "").strip().lower()
        password = os.environ.get("AEGIS_ADMIN_PASSWORD", "")
        if email and password:
            if len(password) < 12:
                raise RuntimeError("AEGIS_ADMIN_PASSWORD must contain at least 12 characters")
            existing = db.execute(
                "SELECT id FROM principals WHERE tenant_id=? AND email=?",
                (DEFAULT_TENANT_ID, email),
            ).fetchone()
            if not existing:
                db.execute(
                    """INSERT INTO principals
                       (id,tenant_id,email,password_hash,role,created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), DEFAULT_TENANT_ID, email,
                     hash_password(password), "super_admin", now_iso()),
                )
        db.commit()
    finally:
        db.close()


def tenant_data_path(tenant_id, default_path):
    if not isinstance(tenant_id, str) or not _TENANT_ID_PATTERN.fullmatch(tenant_id):
        raise ValueError("Invalid tenant identifier")
    if tenant_id == DEFAULT_TENANT_ID:
        return default_path
    directory = os.path.join(ROOT_DIR, "tenant_data")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, tenant_id + ".db")


def ensure_execution_tables(path):
    db = sqlite3.connect(path, timeout=10)
    try:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS executed_decisions (
            decision_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            executed_at TEXT NOT NULL,
            outcome TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pending_commands (
            id TEXT PRIMARY KEY,
            decision_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            params_json TEXT NOT NULL,
            token TEXT NOT NULL,
            nonce TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            response_json TEXT,
            responded_at TEXT,
            UNIQUE (decision_id)
        );
        CREATE INDEX IF NOT EXISTS idx_pending_agent_status
            ON pending_commands(agent_id, status, expires_at);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_command_decision
            ON pending_commands(decision_id);
        CREATE TABLE IF NOT EXISTS approval_requests (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            decision_id TEXT NOT NULL UNIQUE,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            reason TEXT NOT NULL,
            required_role TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            expires_at REAL NOT NULL,
            approved_at TEXT,
            approved_by TEXT
        );
        """)
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise
    finally:
        db.close()


def ensure_tenant_data_db(tenant_id, default_path):
    path = tenant_data_path(tenant_id, default_path)
    if path == default_path or os.path.exists(path):
        return path

    source = sqlite3.connect(default_path)
    target = sqlite3.connect(path)
    try:
        schema = source.execute(
            """SELECT sql FROM sqlite_master
               WHERE sql IS NOT NULL AND type IN ('table','index','trigger')
               AND name NOT LIKE 'sqlite_%' ORDER BY type='table' DESC"""
        ).fetchall()
        for (statement,) in schema:
            target.execute(statement)
        target.commit()
    except Exception:
        target.close()
        source.close()
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    target.close()
    source.close()
    return path


def get_principal(email, tenant_id=None):
    db = get_identity_db()
    try:
        if tenant_id:
            row = db.execute(
                "SELECT * FROM principals WHERE tenant_id=? AND email=? COLLATE NOCASE",
                (tenant_id, email),
            ).fetchone()
        else:
            rows = db.execute(
                "SELECT * FROM principals WHERE email=? COLLATE NOCASE AND is_active=1",
                (email,),
            ).fetchall()
            row = rows[0] if len(rows) == 1 else None
        return dict(row) if row else None
    finally:
        db.close()


def principal_by_id(principal_id, tenant_id):
    db = get_identity_db()
    try:
        row = db.execute(
            "SELECT * FROM principals WHERE id=? AND tenant_id=?",
            (principal_id, tenant_id),
        ).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def record_login(principal_id, tenant_id):
    db = get_identity_db()
    try:
        db.execute(
            "UPDATE principals SET last_login=? WHERE id=? AND tenant_id=?",
            (now_iso(), principal_id, tenant_id),
        )
        db.commit()
    finally:
        db.close()


def create_principal(tenant_id, email, password, role):
    if role not in {"viewer", "analyst", "security_admin", "compliance_officer", "super_admin"}:
        raise ValueError("Unsupported role")
    db = get_identity_db()
    principal_id = str(uuid.uuid4())
    try:
        db.execute(
            """INSERT INTO principals
               (id,tenant_id,email,password_hash,role,created_at)
               VALUES (?,?,?,?,?,?)""",
            (principal_id, tenant_id, email.strip().lower(),
             hash_password(password), role, now_iso()),
        )
        db.commit()
        return principal_id
    finally:
        db.close()


def list_principals(tenant_id):
    db = get_identity_db()
    try:
        return [dict(row) for row in db.execute(
            """SELECT id,email,role,is_active,last_login,created_at
               FROM principals WHERE tenant_id=? ORDER BY email""",
            (tenant_id,),
        )]
    finally:
        db.close()


def tenant_exists(tenant_id):
    db = get_identity_db()
    try:
        return db.execute("SELECT 1 FROM tenants WHERE id=?", (tenant_id,)).fetchone() is not None
    finally:
        db.close()


def list_tenants():
    db = get_identity_db()
    try:
        return [row["id"] for row in db.execute("SELECT id FROM tenants ORDER BY id")]
    finally:
        db.close()


def register_agent(tenant_id, hostname):
    if not isinstance(hostname, str) or not hostname.strip() or len(hostname) > 255:
        raise ValueError("A hostname of at most 255 characters is required")
    master_secret = os.environ.get("AEGIS_AGENT_SECRET", "")
    if len(master_secret.encode("utf-8")) < 32:
        raise RuntimeError("AEGIS_AGENT_SECRET must contain at least 32 bytes")
    agent_id = str(uuid.uuid4())
    db = get_identity_db()
    try:
        db.execute(
            "INSERT INTO agents (id,tenant_id,hostname,created_at) VALUES (?,?,?,?)",
            (agent_id, tenant_id, hostname.strip(), now_iso()),
        )
        db.commit()
    finally:
        db.close()
    return agent_id, hmac.new(
        master_secret.encode("utf-8"),
        b"aegis-agent:" + agent_id.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def get_agent_secret(agent_id):
    master_secret = os.environ.get("AEGIS_AGENT_SECRET", "")
    if len(master_secret.encode("utf-8")) < 32:
        raise RuntimeError("AEGIS_AGENT_SECRET must contain at least 32 bytes")
    db = get_identity_db()
    try:
        agent = db.execute(
            "SELECT id FROM agents WHERE id=? AND is_active=1",
            (agent_id,),
        ).fetchone()
    finally:
        db.close()
    if not agent:
        raise LookupError("Unknown or inactive agent")
    return hmac.new(
        master_secret.encode("utf-8"),
        b"aegis-agent:" + agent_id.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def get_agent(agent_id):
    db = get_identity_db()
    try:
        row = db.execute(
            "SELECT id,tenant_id,hostname,is_active FROM agents WHERE id=?",
            (agent_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        db.close()


def agent_is_online(agent_id, tenant_id, within_seconds=120):
    db = get_identity_db()
    try:
        return db.execute(
            """SELECT 1 FROM agents
               WHERE id=? AND tenant_id=? AND is_active=1
                 AND julianday(last_seen)>=julianday('now', ?)""",
            (agent_id, tenant_id, f"-{within_seconds} seconds"),
        ).fetchone() is not None
    finally:
        db.close()


def touch_agent(agent_id):
    db = get_identity_db()
    try:
        db.execute(
            "UPDATE agents SET last_seen=? WHERE id=? AND is_active=1",
            (now_iso(), agent_id),
        )
        db.commit()
    finally:
        db.close()


def create_tenant(tenant_id, name):
    if not isinstance(tenant_id, str) or not _TENANT_ID_PATTERN.fullmatch(tenant_id):
        raise ValueError("Invalid tenant identifier")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError("Tenant name is required and must be at most 120 characters")
    db = get_identity_db()
    try:
        db.execute(
            "INSERT INTO tenants (id,name,created_at) VALUES (?,?,?)",
            (tenant_id, name.strip(), now_iso()),
        )
        db.commit()
    finally:
        db.close()


def delete_tenant(tenant_id):
    if tenant_id == DEFAULT_TENANT_ID:
        raise ValueError("The default tenant cannot be deleted")
    db = get_identity_db()
    try:
        db.execute("DELETE FROM principals WHERE tenant_id=?", (tenant_id,))
        db.execute("DELETE FROM tenants WHERE id=?", (tenant_id,))
        db.commit()
    finally:
        db.close()


def set_principal_active(principal_id, tenant_id, is_active):
    db = get_identity_db()
    try:
        cursor = db.execute(
            "UPDATE principals SET is_active=? WHERE id=? AND tenant_id=?",
            (int(bool(is_active)), principal_id, tenant_id),
        )
        db.commit()
        return cursor.rowcount == 1
    finally:
        db.close()


def revoke_token(token_id, expires_at):
    db = get_identity_db()
    try:
        db.execute("DELETE FROM revoked_tokens WHERE expires_at<=?", (int(datetime.utcnow().timestamp()),))
        db.execute(
            "INSERT OR REPLACE INTO revoked_tokens (token_id,expires_at) VALUES (?,?)",
            (token_id, int(expires_at)),
        )
        db.commit()
    finally:
        db.close()


def token_is_revoked(token_id):
    db = get_identity_db()
    try:
        row = db.execute(
            "SELECT 1 FROM revoked_tokens WHERE token_id=? AND expires_at>?",
            (token_id, int(datetime.utcnow().timestamp())),
        ).fetchone()
        return row is not None
    finally:
        db.close()
