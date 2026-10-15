"""
AEGIS Flask prototype: agent telemetry → AI decision → approval queue → dashboard.
"""
import os, json, time, threading, queue, sqlite3, hashlib, hmac, logging, uuid, ipaddress

from flask import Flask, g, has_app_context, jsonify, request, send_file, Response
from datetime import datetime, timedelta
from services.core import (
    COMMAND_SECRET,
    build_command_token,
    create_access_token,
    decode_access_token,
    verify_password,
    verify_command_token,
)
from services.database import (
    DEFAULT_TENANT_ID,
    agent_is_online,
    create_principal,
    create_tenant,
    delete_tenant,
    ensure_execution_tables,
    ensure_tenant_data_db,
    get_agent,
    get_agent_secret,
    get_principal,
    init_identity,
    list_tenants,
    list_principals,
    principal_by_id,
    register_agent,
    record_login,
    revoke_token,
    set_principal_active,
    tenant_exists,
    tenant_data_path,
    touch_agent,
    token_is_revoked,
)

import numpy as np
from ai_engine.models import registry

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer): return int(obj)
        if isinstance(obj, np.floating): return float(obj)
        if isinstance(obj, np.bool_): return bool(obj)
        if isinstance(obj, np.ndarray): return obj.tolist()
        return super().default(obj)

def safe_json(obj):
    return json.loads(json.dumps(obj, cls=NumpyEncoder))


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("AEGIS_DB_PATH", os.path.join(ROOT_DIR, "aegis3.db"))
AGENT_SECRET = os.environ.get("AEGIS_AGENT_SECRET", "")
AGENT_MAX_SKEW_SECONDS = int(os.environ.get("AEGIS_AGENT_MAX_SKEW_SECONDS", "300"))
EVENT_MAX_SKEW_SECONDS = int(os.environ.get("AEGIS_EVENT_MAX_SKEW_SECONDS", "60"))
_ingest_lock = threading.Lock()
_decision_worker_wakeup = threading.Event()
_decision_worker_started = False
_execution_dispatcher_started = False
_dispatch_wait_notices = set()
_dispatch_wait_lock = threading.Lock()
_COMMAND_FAILURE_DETAILS = frozenset({
    "agent_id_mismatch", "decision_stale", "nonce_reuse",
    "unsupported_action", "invalid_ip", "unsafe_ip", "signature_failed",
    "firewall_unsupported_platform", "firewall_permission_denied",
    "firewall_unavailable", "firewall_command_failed",
})
_COMMAND_SUCCESS_DETAILS = frozenset({"dry_run", "blocked", "already_blocked"})
logging.basicConfig(level=os.environ.get("AEGIS_LOG_LEVEL", "INFO"))
logger = logging.getLogger("aegis")

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    db_path = getattr(g, "db_path", DB) if has_app_context() else DB
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    db = sqlite3.connect(db_path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


@app.before_request
def authenticate_api_request():
    if not request.path.startswith("/api/"):
        return None
    if request.path in {"/api/health", "/api/auth/login", "/api/agent/data"}:
        return None
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return jsonify({"error": "authentication required"}), 401
    try:
        claims = decode_access_token(authorization[7:].strip())
    except ValueError:
        return jsonify({"error": "invalid or expired access token"}), 401
    if token_is_revoked(claims["jti"]):
        return jsonify({"error": "access token has been revoked"}), 401
    principal = principal_by_id(claims["sub"], claims["tenant_id"])
    if not principal or not principal["is_active"] or principal["role"] != claims["role"]:
        return jsonify({"error": "account is inactive or token claims are stale"}), 401
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and principal["role"] == "viewer":
        return jsonify({"error": "insufficient role"}), 403
    try:
        g.db_path = ensure_tenant_data_db(claims["tenant_id"], DB)
    except (OSError, sqlite3.Error, ValueError):
        logger.exception("Unable to initialize tenant data database")
        return jsonify({"error": "tenant database unavailable"}), 500
    g.principal = principal
    g.tenant_id = claims["tenant_id"]
    return None

def qone(sql, p=()):
    db=get_db(); r=db.execute(sql,p).fetchone(); db.close()
    return dict(r) if r else None

def qall(sql, p=()):
    db=get_db(); rows=db.execute(sql,p).fetchall(); db.close()
    return [dict(r) for r in rows]

def exe(sql, p=()):
    db=get_db(); cur=db.execute(sql,p); db.commit(); lid=cur.lastrowid; db.close()
    return lid

def now(): return datetime.utcnow().isoformat()+"Z"

def remove_legacy_demo_fixtures(db_path):
    db = sqlite3.connect(db_path, timeout=10)
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS app_migrations (
                migration_id TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        """)
        migration_id = "remove_legacy_demo_fixtures_v1"
        if db.execute(
            "SELECT 1 FROM app_migrations WHERE migration_id=?",
            (migration_id,),
        ).fetchone():
            return

        simulated_hosts = (
            "ws-victim-01", "srv-prod-01", "ws-finance-03",
            "ws-dev-07", "ws-0042",
        )
        placeholders = ",".join("?" for _ in simulated_hosts)
        for table, column in (
            ("alerts", "source"),
            ("ai_decisions", "hostname"),
            ("agent_telemetry", "hostname"),
            ("agent_status", "hostname"),
            ("assets", "hostname"),
            ("response_actions", "target"),
            ("threat_events", "source"),
        ):
            db.execute(
                f"DELETE FROM {table} WHERE {column} IN ({placeholders})",
                simulated_hosts,
            )

        db.execute("DELETE FROM threat_events WHERE details LIKE 'Seeded event #%'" )
        db.execute(
            "DELETE FROM alerts WHERE source='185.234.218.47' "
            "AND title LIKE '%Brute Force%'"
        )
        db.execute(
            "DELETE FROM blocked_ips WHERE ip='185.234.218.47' "
            "AND reason='Brute force — AI auto-blocked'"
        )
        db.execute(
            """DELETE FROM users WHERE email IN
               ('sadmin@acme.com','j.kimani@acme.com','m.odhiambo@acme.com',
                't.waweru@acme.com')"""
        )
        db.execute(
            """DELETE FROM compliance_frameworks WHERE
               (name='ISO 27001' AND score_percent=82) OR
               (name='GDPR' AND score_percent=91) OR
               (name='SOC 2 Type II' AND score_percent=68)"""
        )
        db.execute(
            """DELETE FROM darkweb_exposures WHERE
               (email='j.kimani@acmecorp.com' AND found_in='RockYou2024 leak') OR
               (email='admin@acmecorp.com' AND found_in='LinkedIn 2021')"""
        )
        db.execute(
            """DELETE FROM playbooks WHERE name IN
               ('Ransomware Response','Brute Force Shield','Suspicious Login',
                'Unknown Device','AI Unknown Threat')"""
        )
        db.execute(
            """DELETE FROM intel_feeds WHERE
               (name='AlienVault OTX' AND source='alienvault.com') OR
               (name='MISP Feed' AND source='misp-project.org') OR
               (name='Recorded Future' AND source='recordedfuture.com') OR
               (name='Abuse.ch URLhaus' AND source='urlhaus.abuse.ch') OR
               (name='Spamhaus' AND source='spamhaus.org')"""
        )
        db.execute(
            """DELETE FROM notification_channels WHERE
               (channel_name='email' AND is_enabled=1) OR
               (channel_name='telegram' AND is_enabled=1) OR
               (channel_name='whatsapp' AND is_enabled=0) OR
               (channel_name='sms' AND is_enabled=0)"""
        )
        db.execute(
            "INSERT INTO app_migrations (migration_id,applied_at) VALUES (?,?)",
            (migration_id, now()),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        logger.exception("Unable to remove known legacy demo fixtures from %s", db_path)
        raise
    finally:
        db.close()

def audit(action, target, details, by="system"):
    timestamp = now()
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        previous = db.execute(
            "SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else ""
        entry = {
            "action": action,
            "performed_by": by,
            "target": target,
            "details": details,
            "timestamp": timestamp,
            "previous_hash": previous_hash,
        }
        entry_hash = hashlib.sha256(
            json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        db.execute(
            """INSERT INTO audit_log
               (action,performed_by,target,details,timestamp,previous_hash,entry_hash)
               VALUES (?,?,?,?,?,?,?)""",
            (action, by, target, details, timestamp, previous_hash, entry_hash),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def verify_audit_chain():
    rows = qall(
        """SELECT action,performed_by,target,details,timestamp,previous_hash,entry_hash
           FROM audit_log ORDER BY id"""
    )
    previous_hash = ""
    for row in rows:
        if not row["entry_hash"]:
            return False
        entry = {
            "action": row["action"],
            "performed_by": row["performed_by"],
            "target": row["target"],
            "details": row["details"],
            "timestamp": row["timestamp"],
            "previous_hash": previous_hash,
        }
        expected = hashlib.sha256(
            json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if row["previous_hash"] != previous_hash or not hmac.compare_digest(row["entry_hash"], expected):
            return False
        previous_hash = row["entry_hash"]
    return True


def verify_agent_event_chain():
    rows = qall(
        """SELECT event_id,payload_hash,previous_hash,event_hash,created_at
           FROM agent_events ORDER BY rowid"""
    )
    previous_hash = ""
    for row in rows:
        expected = hashlib.sha256(
            f"{row['event_id']}.{row['payload_hash']}.{previous_hash}.{row['created_at']}".encode("utf-8")
        ).hexdigest()
        if row["previous_hash"] != previous_hash or not hmac.compare_digest(row["event_hash"], expected):
            return False
        previous_hash = row["event_hash"]
    return True

# ── SSE ───────────────────────────────────────────────────────────────────────
_sse_clients = []
_sse_lock    = threading.Lock()

def broadcast(etype, data, tenant_id=None):
    if tenant_id is None:
        tenant_id = g.tenant_id if has_app_context() and hasattr(g, "tenant_id") else DEFAULT_TENANT_ID
    payload = f"data: {json.dumps({'type':etype,'payload':data,'ts':now()})}\n\n"
    with _sse_lock:
        dead = []
        for client_tenant_id, q in _sse_clients:
            if client_tenant_id != tenant_id:
                continue
            try: q.put_nowait(payload)
            except queue.Full: dead.append((client_tenant_id, q))
        for client in dead:
            _sse_clients.remove(client)


def _active_alert_snapshot(db_path):
    db = sqlite3.connect(db_path, timeout=5)
    try:
        rows = db.execute(
            """SELECT id,severity,title,source,timestamp,status FROM alerts
               WHERE status='active' ORDER BY id"""
        ).fetchall()
        serialized = json.dumps(rows, separators=(",", ":"), default=list)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    finally:
        db.close()


def process_pending_events_once(tenant_id, limit=100):
    """Persist deterministic brute-force decisions from queued tenant events."""
    db_path = tenant_data_path(tenant_id, DB)
    if not os.path.exists(db_path):
        return 0
    db = sqlite3.connect(db_path, timeout=10)
    db.row_factory = sqlite3.Row
    completed = 0
    try:
        pending_ids = [
            row["id"] for row in db.execute(
                "SELECT id FROM events WHERE processed=0 ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()
        ]
        for event_row_id in pending_ids:
            alert_payload = None
            db.execute("BEGIN IMMEDIATE")
            event = db.execute(
                "SELECT * FROM events WHERE id=? AND processed=0",
                (event_row_id,),
            ).fetchone()
            if not event:
                db.rollback()
                continue
            try:
                payload = json.loads(event["payload_json"])
                failed_logins = payload["failed_logins"]
                if event["event_type"] == "auth_failure" and failed_logins >= 10:
                    decision_id = str(uuid.uuid4())
                    severity = "high" if failed_logins < 50 else "critical"
                    confidence = min(1.0, failed_logins / 100.0)
                    reason = f"{failed_logins} failed logins in 60s"
                    created_at = now()
                    db.execute(
                        """INSERT INTO decisions
                           (decision_id,event_id,agent_id,event_hash,recommended_action,
                                    severity,confidence,reason,created_at,status,required_approval_level)
                                   VALUES (?,?,?,?,?,?,?,?,?,'pending','security_admin')""",
                        (decision_id, event["event_id"], event["agent_id"], event["event_hash"],
                         "block_ip", severity, confidence, reason, created_at),
                    )
                    title = f"Brute force: {reason}"
                    alert_id = db.execute(
                        """INSERT INTO alerts
                           (severity,title,description,alert_type,source,timestamp,status,
                            ai_confidence,ai_risk_score,ai_explanation,event_id,decision_id)
                           VALUES (?,?,?,?,?,?,'active',?,?,?,?,?)""",
                        (severity, title, reason, "brute_force", payload["hostname"], created_at,
                         confidence, confidence, reason, event["event_id"], decision_id),
                    ).lastrowid
                    db.execute(
                        """INSERT INTO threat_events (timestamp,event_type,source,details,score)
                           VALUES (?,?,?,?,?)""",
                        (created_at, "brute_force", payload["hostname"], reason,
                         int(confidence * 100)),
                    )
                    alert_payload = {
                        "id": alert_id,
                        "event_id": event["event_id"],
                        "decision_id": decision_id,
                        "severity": severity,
                        "title": title,
                        "source": payload["hostname"],
                        "confidence": confidence,
                        "created_at": created_at,
                    }
                    db.execute(
                        "UPDATE events SET processed=1,processed_at=?,decision_id=? WHERE id=?",
                        (created_at, decision_id, event_row_id),
                    )
                else:
                    db.execute(
                        "UPDATE events SET processed=1,processed_at=? WHERE id=?",
                        (now(), event_row_id),
                    )
                db.commit()
                completed += 1
            except Exception:
                db.rollback()
                logger.exception(
                    "Decision worker failed for persisted event row %s in tenant %s",
                    event_row_id,
                    tenant_id,
                )
                continue
            if alert_payload:
                broadcast("alert_created", alert_payload, tenant_id=tenant_id)
        return completed
    finally:
        db.close()


def _decision_worker():
    while True:
        try:
            for tenant_id in list_tenants():
                process_pending_events_once(tenant_id)
        except Exception:
            logger.exception("SQLite decision worker cycle failed")
        _decision_worker_wakeup.wait(timeout=1.0)
        _decision_worker_wakeup.clear()


def start_decision_worker():
    global _decision_worker_started
    if _decision_worker_started:
        return
    threading.Thread(target=_decision_worker, name="aegis-decision-worker", daemon=True).start()
    _decision_worker_started = True


def _params_for_action(db, decision):
    if decision["recommended_action"] != "block_ip":
        return None
    event = db.execute(
        "SELECT payload_json FROM events WHERE agent_id=? AND event_id=?",
        (decision["agent_id"], decision["event_id"]),
    ).fetchone()
    if not event:
        return None
    try:
        payload = json.loads(event["payload_json"])
        source_ip = payload.get("source_ip")
        address = ipaddress.ip_address(source_ip)
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if not address.is_global:
        return None
    return {"ip": str(address)}


def _log_dispatch_wait(decision_id, message, *args):
    with _dispatch_wait_lock:
        if decision_id in _dispatch_wait_notices:
            return
        _dispatch_wait_notices.add(decision_id)
    logger.warning(message, *args)


def _dispatch_one(tenant_id, decision_id):
    db_path = tenant_data_path(tenant_id, DB)
    if not os.path.exists(db_path):
        return
    db = sqlite3.connect(db_path, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("BEGIN IMMEDIATE")
        decision = db.execute(
            """SELECT d.*,e.event_timestamp FROM decisions d
               JOIN events e ON e.agent_id=d.agent_id AND e.event_id=d.event_id
               WHERE d.decision_id=?""",
            (decision_id,),
        ).fetchone()
        if not decision or decision["status"] != "pending":
            db.rollback()
            return

        executed = db.execute(
            "SELECT outcome FROM executed_decisions WHERE decision_id=?",
            (decision_id,),
        ).fetchone()
        if executed:
            db.rollback()
            return

        age = time.time() - decision["event_timestamp"]
        if age > 30 or age < -5:
            db.execute(
                """INSERT INTO executed_decisions
                   (decision_id,tenant_id,executed_at,outcome) VALUES (?,?,?,?)""",
                (decision_id, tenant_id, now(), "stale"),
            )
            db.execute(
                "UPDATE decisions SET status='rejected_stale' WHERE decision_id=?",
                (decision_id,),
            )
            db.commit()
            logger.info("dispatch_rejected_stale decision_id=%s", decision_id)
            return

        approval_level = decision["required_approval_level"] or "none"
        if approval_level != "none":
            approval = db.execute(
                "SELECT status,expires_at FROM approval_requests WHERE decision_id=?",
                (decision_id,),
            ).fetchone()
            if not approval:
                db.execute(
                    """INSERT INTO approval_requests
                       (id,tenant_id,decision_id,action,target,reason,required_role,
                        status,created_at,expires_at)
                       VALUES (?,?,?,?,?,?,?,'pending',?,?)""",
                    (
                        str(uuid.uuid4()), tenant_id, decision_id,
                        decision["recommended_action"], decision["agent_id"],
                        "Auto-generated by dispatcher", approval_level,
                        now(), time.time() + 300,
                    ),
                )
                db.commit()
                logger.info("dispatch_waiting_approval decision_id=%s", decision_id)
                return
            if approval["status"] != "approved" or approval["expires_at"] <= time.time():
                if approval["status"] == "pending" and approval["expires_at"] <= time.time():
                    db.execute(
                        "UPDATE approval_requests SET status='expired' WHERE decision_id=?",
                        (decision_id,),
                    )
                    db.commit()
                    return
                db.rollback()
                return

        agent = get_agent(decision["agent_id"])
        if (
            not agent or not agent["is_active"]
            or agent["tenant_id"] != tenant_id
            or not agent_is_online(decision["agent_id"], tenant_id)
        ):
            db.rollback()
            _log_dispatch_wait(
                decision_id, "dispatch_no_online_agent decision_id=%s", decision_id,
            )
            return

        params = _params_for_action(db, decision)
        if params is None:
            db.rollback()
            _log_dispatch_wait(
                decision_id,
                "dispatch_missing_or_unsafe_parameters decision_id=%s",
                decision_id,
            )
            return
        if not COMMAND_SECRET:
            db.rollback()
            logger.error("dispatch_not_configured command signing secret is unavailable")
            return

        token, nonce = build_command_token(
            decision["agent_id"],
            decision["recommended_action"],
            params,
            decision["event_timestamp"],
            ttl=30,
        )
        token_payload = verify_command_token(token)
        issued_at = now()
        expires_at = float(token_payload["exp"])
        command_id = str(uuid.uuid4())
        db.execute(
            """INSERT INTO pending_commands
               (id,decision_id,tenant_id,agent_id,action,params_json,token,nonce,
                issued_at,expires_at,status)
               VALUES (?,?,?,?,?,?,?,?,?,?,'pending')""",
            (
                command_id, decision_id, tenant_id, decision["agent_id"],
                decision["recommended_action"],
                json.dumps(params, sort_keys=True, separators=(",", ":")),
                token, nonce, issued_at, expires_at,
            ),
        )
        db.execute(
            "UPDATE decisions SET status='dispatched' WHERE decision_id=? AND status='pending'",
            (decision_id,),
        )
        db.execute(
            """INSERT INTO executed_decisions
               (decision_id,tenant_id,executed_at,outcome) VALUES (?,?,?,?)""",
            (decision_id, tenant_id, issued_at, "dispatched"),
        )
        db.commit()
        with _dispatch_wait_lock:
            _dispatch_wait_notices.discard(decision_id)
        logger.info("dispatch_command decision_id=%s command_id=%s", decision_id, command_id)
    except sqlite3.IntegrityError:
        db.rollback()
        logger.info("already_dispatched decision_id=%s", decision_id)
    except Exception:
        db.rollback()
        logger.exception("Unable to dispatch decision_id=%s", decision_id)
    finally:
        db.close()


def _run_dispatcher_once(tenant_id=None, limit=50):
    tenants = [tenant_id] if tenant_id else list_tenants()
    for current_tenant in tenants:
        db_path = tenant_data_path(current_tenant, DB)
        if not os.path.exists(db_path):
            continue
        db = sqlite3.connect(db_path, timeout=10)
        try:
            pending = db.execute(
                "SELECT decision_id FROM decisions WHERE status='pending' ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            db.close()
        for (decision_id,) in pending:
            _dispatch_one(current_tenant, decision_id)


def _execution_dispatcher():
    while True:
        try:
            _run_dispatcher_once()
        except Exception:
            logger.exception("Execution dispatcher cycle failed")
        time.sleep(0.5)


def start_execution_dispatcher():
    global _execution_dispatcher_started
    if _execution_dispatcher_started:
        return
    if not COMMAND_SECRET:
        logger.warning("Execution dispatcher disabled: AEGIS_COMMAND_SECRET is not configured")
        return
    threading.Thread(
        target=_execution_dispatcher,
        name="aegis-execution-dispatcher",
        daemon=True,
    ).start()
    _execution_dispatcher_started = True

# ── Schema ────────────────────────────────────────────────────────────────────
def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT UNIQUE, ip TEXT, platform TEXT, os_version TEXT,
        risk_level TEXT DEFAULT 'low', vulnerabilities TEXT DEFAULT '',
        status TEXT DEFAULT 'online', last_seen TEXT,
        cpu_percent REAL, memory_percent REAL, disk_percent REAL,
        open_ports TEXT, process_count INTEGER
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        severity TEXT, title TEXT, description TEXT,
        alert_type TEXT, source TEXT, timestamp TEXT, status TEXT DEFAULT 'active',
        ai_confidence REAL DEFAULT 0, ai_risk_score REAL DEFAULT 0,
        ai_anomaly_score REAL DEFAULT 0, ai_explanation TEXT DEFAULT '',
        ai_evidence TEXT DEFAULT '[]', ai_recommended_actions TEXT DEFAULT '[]',
        ai_why_not_normal TEXT DEFAULT '[]', ai_model_votes TEXT DEFAULT '{}',
        event_id TEXT, decision_id TEXT
    );
    CREATE TABLE IF NOT EXISTS ai_decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT, threat_type TEXT, severity TEXT,
        confidence REAL, anomaly_score REAL, risk_score REAL,
        explanation TEXT, evidence TEXT, recommended_actions TEXT,
        model_votes TEXT, features TEXT, attack_chain TEXT,
        processing_ms REAL, timestamp TEXT,
        feedback TEXT DEFAULT NULL
    );
    CREATE TABLE IF NOT EXISTS threat_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, event_type TEXT, source TEXT, details TEXT, score INTEGER
    );
    CREATE TABLE IF NOT EXISTS response_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT, target TEXT, description TEXT,
        status TEXT DEFAULT 'completed', timestamp TEXT,
        triggered_by TEXT DEFAULT 'auto'
    );
    CREATE TABLE IF NOT EXISTS playbooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, description TEXT, steps TEXT,
        trigger_count INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, email TEXT UNIQUE,
        role TEXT DEFAULT 'analyst', is_flagged INTEGER DEFAULT 0, last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS compliance_frameworks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, score_percent INTEGER, controls_status TEXT
    );
    CREATE TABLE IF NOT EXISTS darkweb_exposures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT, found_in TEXT, password_hash_exposed INTEGER DEFAULT 0,
        remediation_status TEXT DEFAULT 'pending', detected_at TEXT
    );
    CREATE TABLE IF NOT EXISTS agent_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT UNIQUE, platform TEXT, status TEXT DEFAULT 'online',
        last_heartbeat TEXT, version TEXT DEFAULT 'v3.0.0-ai',
        cpu_usage REAL DEFAULT 0, events_buffered INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS notification_channels (
        channel_name TEXT PRIMARY KEY, is_enabled INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY, reason TEXT, blocked_at TEXT, blocked_by TEXT DEFAULT 'system'
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT, performed_by TEXT DEFAULT 'admin',
        target TEXT, details TEXT, timestamp TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS agent_events (
        event_id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        result_json TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS intel_feeds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, source TEXT, description TEXT,
        last_updated TEXT, ioc_count INTEGER DEFAULT 0, status TEXT DEFAULT 'active'
    );
    CREATE TABLE IF NOT EXISTS agent_telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT, timestamp TEXT,
        cpu_percent REAL, memory_percent REAL, process_count INTEGER,
        failed_logins INTEGER, alert_count INTEGER, ai_threat_type TEXT,
        ai_confidence REAL, ai_risk_score REAL
    );
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        event_timestamp INTEGER NOT NULL,
        prev_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        received_at TEXT NOT NULL,
        processed INTEGER NOT NULL DEFAULT 0,
        processed_at TEXT,
        decision_id TEXT,
        UNIQUE (agent_id,event_id)
    );
    CREATE INDEX IF NOT EXISTS idx_events_pending ON events(processed,received_at);
    CREATE TABLE IF NOT EXISTS agent_chain_heads (
        agent_id TEXT PRIMARY KEY,
        event_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS decisions (
        decision_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        recommended_action TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        required_approval_level TEXT NOT NULL DEFAULT 'none',
        UNIQUE (agent_id,event_id)
    );
    """)
    decision_columns = {row["name"] for row in db.execute("PRAGMA table_info(decisions)")}
    if "status" not in decision_columns:
        db.execute("ALTER TABLE decisions ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
    if "required_approval_level" not in decision_columns:
        db.execute(
            "ALTER TABLE decisions ADD COLUMN required_approval_level TEXT NOT NULL DEFAULT 'none'"
        )
    alert_columns = {row["name"] for row in db.execute("PRAGMA table_info(alerts)")}
    if "event_id" not in alert_columns:
        db.execute("ALTER TABLE alerts ADD COLUMN event_id TEXT")
    if "decision_id" not in alert_columns:
        db.execute("ALTER TABLE alerts ADD COLUMN decision_id TEXT")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id)")
    audit_columns = {row["name"] for row in db.execute("PRAGMA table_info(audit_log)")}
    if "previous_hash" not in audit_columns:
        db.execute("ALTER TABLE audit_log ADD COLUMN previous_hash TEXT")
    if "entry_hash" not in audit_columns:
        db.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
    if db.execute("SELECT 1 FROM audit_log WHERE entry_hash IS NOT NULL LIMIT 1").fetchone() is None:
        previous_hash = ""
        for row in db.execute(
            "SELECT id,action,performed_by,target,details,timestamp FROM audit_log ORDER BY id"
        ).fetchall():
            entry = {
                "action": row["action"],
                "performed_by": row["performed_by"],
                "target": row["target"],
                "details": row["details"],
                "timestamp": row["timestamp"],
                "previous_hash": previous_hash,
            }
            entry_hash = hashlib.sha256(
                json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            db.execute(
                "UPDATE audit_log SET previous_hash=?,entry_hash=? WHERE id=?",
                (previous_hash, entry_hash, row["id"]),
            )
            previous_hash = entry_hash
    db.commit()

    db.commit()
    db.close()
    init_identity()
    for tenant_id in list_tenants():
        tenant_db_path = tenant_data_path(tenant_id, DB)
        if os.path.exists(tenant_db_path):
            ensure_decision_dispatch_columns(tenant_db_path)
            ensure_execution_tables(tenant_db_path)
            remove_legacy_demo_fixtures(tenant_db_path)


def ensure_decision_dispatch_columns(db_path):
    db = sqlite3.connect(db_path, timeout=10)
    try:
        decision_columns = {
            row[1] for row in db.execute("PRAGMA table_info(decisions)")
        }
        if not decision_columns:
            return
        if "status" not in decision_columns:
            db.execute(
                "ALTER TABLE decisions ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"
            )
        if "required_approval_level" not in decision_columns:
            db.execute(
                """ALTER TABLE decisions ADD COLUMN required_approval_level
                   TEXT NOT NULL DEFAULT 'none'"""
            )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        logger.exception("Unable to migrate decision dispatch columns in %s", db_path)
        raise
    finally:
        db.close()


# ── AI Pipeline ───────────────────────────────────────────────────────────────
# Import AI brain (loaded lazily after models trained)
_brain = None

def get_brain():
    global _brain
    if _brain is None:
        from ai_engine.brain import brain
        _brain = brain
    return _brain

def _response_actions_for(threat_type, severity, hostname):
    """Queue AI recommendations for human approval; never execute them."""
    actions_map = {
        ("ransomware","critical"):           ["isolate_device","backup_trigger","block_c2","notify_admin"],
        ("malware","critical"):              ["isolate_device","kill_process","notify_admin"],
        ("exfiltration","critical"):         ["isolate_device","block_ip","notify_admin"],
        ("brute_force","high"):              ["block_ip","notify_admin"],
        ("brute_force","critical"):          ["block_ip","lock_account","notify_admin"],
        ("lateral_movement","high"):         ["isolate_device","notify_admin"],
        ("privilege_escalation","high"):     ["lock_account","kill_process","notify_admin"],
        ("privilege_escalation","critical"): ["lock_account","isolate_device","notify_admin"],
    }
    descs = {
        "isolate_device":   f"Recommended isolation of {hostname}; approval required",
        "backup_trigger":   "Recommended emergency backup snapshot; approval required",
        "block_c2":         "Recommended C2 destination blocking; approval required",
        "notify_admin":     "Recommended administrator notification; approval required",
        "block_ip":         "Recommended source IP block; approval required",
        "lock_account":     f"Recommended account lock on {hostname}; approval required",
        "kill_process":     f"Recommended process termination on {hostname}; approval required",
    }
    actions = actions_map.get((threat_type, severity), [])
    logged = []
    for a in actions:
        action_id = exe(
            """INSERT INTO response_actions
               (action,target,description,status,timestamp,triggered_by)
               VALUES (?,?,?,'pending_approval',?,?)""",
            (a, hostname, descs.get(a, a), now(), "AI recommendation"),
        )
        logged.append({"id": action_id, "action": a, "description": descs.get(a, a),
                       "status": "pending_approval"})
    return logged

def ingest_and_analyze(raw_data):
    """Full AI pipeline: raw agent data → AI decision → DB → SSE."""
    hostname = raw_data.get("hostname","unknown")
    t0 = time.time()

    # 1. Upsert asset
    ports_str = json.dumps(raw_data.get("open_ports",[]))
    existing = qone("SELECT id FROM assets WHERE hostname=?", (hostname,))
    if existing:
        exe("""UPDATE assets SET platform=?,os_version=?,last_seen=?,cpu_percent=?,
               memory_percent=?,disk_percent=?,open_ports=?,process_count=?,status='online'
               WHERE hostname=?""",
            (raw_data.get("platform",""), raw_data.get("platform_version",""), now(),
             raw_data.get("cpu_percent",0), raw_data.get("memory_percent",0),
             raw_data.get("disk_percent",0), ports_str,
             raw_data.get("process_count",0), hostname))
    else:
        exe("""INSERT INTO assets (hostname,platform,os_version,last_seen,cpu_percent,
               memory_percent,disk_percent,open_ports,process_count) VALUES (?,?,?,?,?,?,?,?,?)""",
            (hostname, raw_data.get("platform",""), raw_data.get("platform_version",""), now(),
             raw_data.get("cpu_percent",0), raw_data.get("memory_percent",0),
             raw_data.get("disk_percent",0), ports_str, raw_data.get("process_count",0)))

    # 2. Heartbeat
    exe("INSERT OR REPLACE INTO agent_status (hostname,platform,status,last_heartbeat,cpu_usage) VALUES (?,?,?,?,?)",
        (hostname, raw_data.get("platform",""), "online", now(), raw_data.get("cpu_percent",0)/100))

    # 3. AI Brain processes data
    brain = get_brain()
    ai = brain.process(raw_data)
    risk_level = (
        "high" if ai["risk_score"] >= 0.7
        else "medium" if ai["risk_score"] >= 0.4
        else "low"
    )
    exe(
        "UPDATE assets SET risk_level=? WHERE hostname=?",
        (risk_level, hostname),
    )

    # 4. Save AI decision record
    did = exe("""INSERT INTO ai_decisions
        (hostname,threat_type,severity,confidence,anomaly_score,risk_score,
         explanation,evidence,recommended_actions,model_votes,features,attack_chain,
         processing_ms,timestamp)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (hostname, ai["threat_type"], ai["severity"],
         ai["confidence"], ai["anomaly_score"], ai["risk_score"],
         ai["explanation"],
         json.dumps(safe_json(ai["evidence"])),
         json.dumps(safe_json(ai["recommended_actions"])),
         json.dumps(safe_json(ai["model_votes"])),
         json.dumps(safe_json(ai["features"])),
         json.dumps(safe_json(ai["attack_chain"])) if ai["attack_chain"] else None,
         ai["processing_ms"], ai["timestamp"]))

    # 5. Create alert if AI says so
    alert_id = None
    responses_logged = []
    if ai["should_alert"]:
        title = {
            "brute_force":          f"AI: Brute Force Attack — {int(ai['features'].get('failed_logins',0))} failed logins",
            "ransomware":           f"AI: Ransomware Detected — {ai['features'].get('disk_write',0):.0f}MB disk write",
            "malware":              f"AI: Malware Process Detected on {hostname}",
            "exfiltration":         f"AI: Data Exfiltration — {ai['features'].get('net_sent',0):.0f}MB egress",
            "lateral_movement":     f"AI: Lateral Movement from {hostname}",
            "privilege_escalation": f"AI: Privilege Escalation on {hostname}",
        }.get(ai["threat_type"], f"AI: Threat Detected — {ai['threat_type']} on {hostname}")

        alert_id = exe("""INSERT INTO alerts
            (severity,title,description,alert_type,source,timestamp,status,
             ai_confidence,ai_risk_score,ai_anomaly_score,ai_explanation,
             ai_evidence,ai_recommended_actions,ai_why_not_normal,ai_model_votes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ai["severity"], title, ai["explanation"][:400],
             ai["threat_type"], hostname, now(), "active",
             ai["confidence"], ai["risk_score"], ai["anomaly_score"],
             ai["explanation"],
             json.dumps(safe_json(ai["evidence"])),
             json.dumps(safe_json(ai["recommended_actions"])),
             json.dumps(safe_json(ai["why_not_normal"])),
             json.dumps(safe_json(ai["model_votes"]))))

        # 6. Queue advisory recommendations for operator review.
        responses_logged = _response_actions_for(ai["threat_type"], ai["severity"], hostname)
        audit("ai_recommendation_created", hostname,
              f"{ai['threat_type']} ({ai['severity']}) confidence={ai['confidence']*100:.0f}% → {len(responses_logged)} recommendations")

        # Attack chain alert
        if ai["attack_chain"]:
            chain = ai["attack_chain"]
            exe("""INSERT INTO alerts (severity,title,description,alert_type,source,timestamp,status,ai_confidence)
                   VALUES (?,?,?,?,?,?,?,?)""",
                ("critical",
                 f"AI: Attack Chain — {chain['chain_name']} ({chain['completion_pct']}% complete)",
                 f"Multi-stage attack pattern detected: {' → '.join(chain['matched_steps'])}",
                 "attack_chain", hostname, now(), "active", 0.92))

    # 7. Telemetry log
    exe("""INSERT INTO agent_telemetry
        (hostname,timestamp,cpu_percent,memory_percent,process_count,
         failed_logins,alert_count,ai_threat_type,ai_confidence,ai_risk_score)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (hostname, now(), raw_data.get("cpu_percent",0), raw_data.get("memory_percent",0),
         raw_data.get("process_count",0), raw_data.get("failed_logins",0),
         1 if ai["should_alert"] else 0,
         ai["threat_type"], ai["confidence"], ai["risk_score"]))

    # 8. Threat event
    if ai["should_alert"]:
        exe("INSERT INTO threat_events (timestamp,event_type,source,details,score) VALUES (?,?,?,?,?)",
            (now(), ai["threat_type"], hostname,
             f"AI: {ai['threat_type']} conf={ai['confidence']:.2f}", int(ai["risk_score"]*100)))

    # 9. SSE broadcast
    broadcast("agent_update", {
        "hostname": hostname, "cpu": ai["features"]["cpu"],
        "memory": ai["features"]["memory"], "new_alert": ai["should_alert"],
    })
    if ai["should_alert"]:
        broadcast("ai_alert", {
            "id": alert_id, "title": f"{ai['threat_type'].replace('_',' ').upper()} on {hostname}",
            "severity": ai["severity"], "confidence": ai["confidence"],
            "explanation": ai["explanation"][:200],
        })

    total_ms = round((time.time()-t0)*1000, 1)

    return {
        "hostname":           hostname,
        "ai_threat_type":     ai["threat_type"],
        "ai_severity":        ai["severity"],
        "ai_confidence":      ai["confidence"],
        "ai_anomaly_score":   ai["anomaly_score"],
        "ai_risk_score":      ai["risk_score"],
        "alert_created":      ai["should_alert"],
        "alert_id":           alert_id,
        "pending_approvals":  len(responses_logged),
        "attack_chain":       ai["attack_chain"],
        "explanation":        ai["explanation"],
        "evidence":           ai["evidence"],
        "processing_ms":      total_ms,
    }

# ── Background Agent ──────────────────────────────────────────────────────────
def _bg_agent():
    """Collects real system data every 20s via local psutil agent."""
    try:
        from agent.collector import AegisAgent
        agent = AegisAgent(hostname="aegis-host-local", tenant_id=DEFAULT_TENANT_ID)
    except Exception:
        logger.exception("Unable to initialize the local telemetry agent")
        return
    while True:
        try:
            data = agent.collect()
            ingest_and_analyze(data)
        except Exception:
            logger.exception("Local telemetry collection or analysis failed")
        time.sleep(20)

# ═══════════════ API ROUTES ═══════════════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    tenant_id = data.get("tenantId") or DEFAULT_TENANT_ID
    if not isinstance(email, str) or not isinstance(password, str) or not isinstance(tenant_id, str):
        return jsonify({"error": "invalid credentials"}), 401
    principal = get_principal(email.strip(), tenant_id)
    if not principal or not principal["is_active"] or not verify_password(password, principal["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401
    try:
        token = create_access_token(principal["id"], principal["tenant_id"], principal["role"])
    except RuntimeError:
        logger.exception("Authentication token signing is not configured")
        return jsonify({"error": "authentication is not configured"}), 503
    record_login(principal["id"], principal["tenant_id"])
    return jsonify({
        "accessToken": token,
        "expiresIn": 900,
        "user": {"id": principal["id"], "email": principal["email"],
                 "role": principal["role"], "tenantId": principal["tenant_id"]},
    })


@app.route('/api/auth/me')
def auth_me():
    principal = g.principal
    return jsonify({
        "id": principal["id"],
        "email": principal["email"],
        "role": principal["role"],
        "tenantId": principal["tenant_id"],
    })


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    claims = decode_access_token(request.headers.get("Authorization", "")[7:].strip())
    revoke_token(claims["jti"], claims["exp"])
    return jsonify({"success": True})


@app.route('/api/admin/tenants', methods=['POST'])
def admin_create_tenant():
    if g.principal["role"] != "super_admin":
        return jsonify({"error": "insufficient role"}), 403
    data = request.get_json(silent=True) or {}
    tenant_id = data.get("tenantId") or "tenant-" + uuid.uuid4().hex
    name = data.get("name")
    email = data.get("adminEmail")
    password = data.get("adminPassword")
    if not isinstance(email, str) or not email.strip() or not isinstance(password, str) or len(password) < 12:
        return jsonify({"error": "an admin email and a 12+ character password are required"}), 400
    created = False
    try:
        create_tenant(tenant_id, name)
        created = True
        ensure_tenant_data_db(tenant_id, DB)
        principal_id = create_principal(tenant_id, email, password, "super_admin")
        audit("tenant_created", tenant_id, name.strip(), g.principal["email"])
        return jsonify({"success": True, "tenantId": tenant_id, "adminId": principal_id}), 201
    except ValueError as exc:
        if created:
            delete_tenant(tenant_id)
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        if created:
            delete_tenant(tenant_id)
        return jsonify({"error": "tenant or admin email already exists"}), 409
    except (OSError, sqlite3.Error):
        if created:
            delete_tenant(tenant_id)
        logger.exception("Tenant provisioning failed")
        return jsonify({"error": "tenant provisioning failed"}), 500


@app.route('/api/agents/register', methods=['POST'])
def register_agent_route():
    if g.principal["role"] not in {"super_admin", "security_admin"}:
        return jsonify({"error": "insufficient role"}), 403
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname")
    try:
        agent_id, secret = register_agent(g.tenant_id, hostname)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError:
        logger.exception("Agent registration is not configured")
        return jsonify({"error": "agent registration is not configured"}), 503
    return jsonify({
        "agent_id": agent_id,
        "tenant_id": g.tenant_id,
        "hostname": hostname.strip(),
        "hmac_secret": secret,
    }), 201


def _authenticate_signed_agent_request(body):
    agent_id = request.headers.get("X-Agent-Id", "").strip()
    timestamp_text = request.headers.get("X-Timestamp", "").strip()
    signature = request.headers.get("X-Signature", "").lower()
    event_id = request.headers.get("X-Event-Id", "").strip()
    if not all((agent_id, timestamp_text, signature, event_id)):
        return None, None, (jsonify({"error": "missing headers"}), 400)
    if not timestamp_text.isdecimal() or len(timestamp_text) > 12 or len(event_id) > 128:
        return None, None, (jsonify({"error": "invalid timestamp or event id"}), 400)
    if abs(int(time.time()) - int(timestamp_text)) > EVENT_MAX_SKEW_SECONDS:
        return None, None, (jsonify({"error": "timestamp_out_of_window"}), 400)

    agent = get_agent(agent_id)
    if not agent or not agent["is_active"]:
        return None, None, (jsonify({"error": "unknown agent"}), 401)
    try:
        secret = get_agent_secret(agent_id)
    except RuntimeError:
        logger.exception("Agent request signing is not configured")
        return None, None, (jsonify({"error": "signed agent requests are not configured"}), 503)
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        timestamp_text.encode("ascii") + b"." + event_id.encode("utf-8") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None, None, (jsonify({"error": "invalid_signature"}), 401)
    return agent, event_id, None


@app.route('/v1/ingest/event', methods=['POST'])
def ingest_event():
    body = request.get_data(cache=True)
    agent, event_id, auth_error = _authenticate_signed_agent_request(body)
    if auth_error:
        return auth_error
    agent_id = agent["id"]
    timestamp_text = request.headers["X-Timestamp"].strip()
    timestamp = int(timestamp_text)

    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "request body must be valid JSON"}), 400
    if not isinstance(payload, dict):
        return jsonify({"error": "event payload must be an object"}), 400
    failed_logins = payload.get("failed_logins")
    if (
        payload.get("event_type") != "auth_failure"
        or not isinstance(failed_logins, int)
        or isinstance(failed_logins, bool)
        or failed_logins < 0
        or payload.get("hostname") != agent["hostname"]
    ):
        return jsonify({"error": "invalid auth_failure event"}), 400
    prev_hash = payload.get("prev_hash")
    if (
        not isinstance(prev_hash, str)
        or len(prev_hash) != 64
        or any(character not in "0123456789abcdef" for character in prev_hash)
    ):
        return jsonify({"error": "invalid prev_hash"}), 400

    try:
        db_path = ensure_tenant_data_db(agent["tenant_id"], DB)
    except (OSError, sqlite3.Error, ValueError):
        logger.exception("Unable to initialize tenant data database for agent event")
        return jsonify({"error": "tenant database unavailable"}), 500

    payload_hash = hashlib.sha256(body).hexdigest()
    event_hash = hashlib.sha256(
        f"{prev_hash}.{timestamp_text}.".encode("ascii") + body
    ).hexdigest()
    db = sqlite3.connect(db_path, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute(
            "SELECT payload_hash,event_hash FROM events WHERE agent_id=? AND event_id=?",
            (agent_id, event_id),
        ).fetchone()
        if existing:
            db.rollback()
            if existing["payload_hash"] != payload_hash:
                return jsonify({"error": "event id reused with a different payload"}), 409
            return jsonify({"status": "duplicate", "event_hash": existing["event_hash"]}), 200

        chain = db.execute(
            "SELECT event_hash FROM agent_chain_heads WHERE agent_id=?",
            (agent_id,),
        ).fetchone()
        expected_prev_hash = chain["event_hash"] if chain else "0" * 64
        if prev_hash != expected_prev_hash:
            db.rollback()
            return jsonify({"error": "chain_broken"}), 409
        received_at = now()
        db.execute(
            """INSERT INTO events
               (agent_id,event_id,event_type,payload_json,payload_hash,event_timestamp,
                prev_hash,event_hash,signature,received_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (agent_id, event_id, payload["event_type"], body.decode("utf-8"),
             payload_hash, timestamp, prev_hash, event_hash, signature, received_at),
        )
        db.execute(
            """INSERT INTO agent_chain_heads (agent_id,event_hash) VALUES (?,?)
               ON CONFLICT(agent_id) DO UPDATE SET event_hash=excluded.event_hash""",
            (agent_id, event_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        duplicate = db.execute(
            "SELECT payload_hash,event_hash FROM events WHERE agent_id=? AND event_id=?",
            (agent_id, event_id),
        ).fetchone()
        if duplicate and duplicate["payload_hash"] == payload_hash:
            return jsonify({"status": "duplicate", "event_hash": duplicate["event_hash"]}), 200
        return jsonify({"error": "event id conflict"}), 409
    except sqlite3.Error:
        db.rollback()
        logger.exception("Unable to persist authenticated event %s", event_id)
        return jsonify({"error": "event persistence failed"}), 503
    finally:
        db.close()

    touch_agent(agent_id)
    _decision_worker_wakeup.set()
    return jsonify({"status": "accepted", "event_hash": event_hash}), 202


@app.route('/v1/agent/commands/<agent_id>')
def poll_agent_commands(agent_id):
    body = request.get_data(cache=True)
    agent, _, auth_error = _authenticate_signed_agent_request(body)
    if auth_error:
        return auth_error
    if agent["id"] != agent_id:
        return jsonify({"error": "agent_id_mismatch"}), 403
    touch_agent(agent_id)
    db_path = ensure_tenant_data_db(agent["tenant_id"], DB)
    db = sqlite3.connect(db_path, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """UPDATE pending_commands SET status='expired'
               WHERE agent_id=? AND tenant_id=? AND status='pending' AND expires_at<=?""",
            (agent_id, agent["tenant_id"], time.time()),
        )
        db.execute(
            """UPDATE decisions SET status='rejected_stale'
               WHERE status='dispatched' AND decision_id IN (
                   SELECT decision_id FROM pending_commands
                   WHERE agent_id=? AND tenant_id=? AND status='expired'
               )""",
            (agent_id, agent["tenant_id"]),
        )
        db.execute(
            """UPDATE executed_decisions SET outcome='expired'
               WHERE decision_id IN (
                   SELECT decision_id FROM pending_commands
                   WHERE agent_id=? AND tenant_id=? AND status='expired'
               ) AND outcome='dispatched'""",
            (agent_id, agent["tenant_id"]),
        )
        rows = db.execute(
            """SELECT id,action,params_json,token,issued_at,expires_at
               FROM pending_commands
               WHERE agent_id=? AND tenant_id=? AND status='pending' AND expires_at>?
               ORDER BY issued_at LIMIT 5""",
            (agent_id, agent["tenant_id"], time.time()),
        ).fetchall()
        db.commit()
        commands = []
        for row in rows:
            try:
                params = json.loads(row["params_json"])
            except json.JSONDecodeError:
                logger.exception("Invalid params_json for pending command %s", row["id"])
                continue
            commands.append({
                "id": row["id"],
                "action": row["action"],
                "params": params,
                "token": row["token"],
                "issued_at": row["issued_at"],
                "expires_at": row["expires_at"],
            })
        return jsonify({"commands": commands})
    except sqlite3.Error:
        db.rollback()
        logger.exception("Unable to load commands for agent %s", agent_id)
        return jsonify({"error": "command queue unavailable"}), 503
    finally:
        db.close()


@app.route('/v1/agent/commands/<command_id>/response', methods=['POST'])
def report_command_response(command_id):
    body = request.get_data(cache=True)
    agent, _, auth_error = _authenticate_signed_agent_request(body)
    if auth_error:
        return auth_error
    try:
        response_data = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "request body must be valid JSON"}), 400
    if not isinstance(response_data, dict):
        return jsonify({"error": "response must be an object"}), 400
    status = response_data.get("status")
    detail = response_data.get("detail")
    duration_ms = response_data.get("duration_ms")
    if (
        response_data.get("command_id") != command_id
        or not isinstance(status, str)
        or status not in {"success", "failed"}
        or not isinstance(detail, str)
        or (
            (status == "success" and detail not in _COMMAND_SUCCESS_DETAILS)
            or (status == "failed" and detail not in _COMMAND_FAILURE_DETAILS)
        )
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, (int, float))
        or not 0 <= duration_ms <= 300000
    ):
        return jsonify({"error": "invalid command response"}), 400

    db_path = ensure_tenant_data_db(agent["tenant_id"], DB)
    db = sqlite3.connect(db_path, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("BEGIN IMMEDIATE")
        command = db.execute(
            """SELECT * FROM pending_commands
               WHERE id=? AND agent_id=? AND tenant_id=?""",
            (command_id, agent["id"], agent["tenant_id"]),
        ).fetchone()
        if not command:
            db.rollback()
            return jsonify({"error": "command not found"}), 404
        if command["status"] != "pending":
            db.rollback()
            return jsonify({"status": "already_recorded"}), 200
        if command["expires_at"] <= time.time():
            db.execute(
                "UPDATE pending_commands SET status='expired' WHERE id=? AND status='pending'",
                (command_id,),
            )
            db.execute(
                "UPDATE decisions SET status='rejected_stale' WHERE decision_id=? AND status='dispatched'",
                (command["decision_id"],),
            )
            db.execute(
                "UPDATE executed_decisions SET outcome='expired' WHERE decision_id=? AND outcome='dispatched'",
                (command["decision_id"],),
            )
            db.commit()
            return jsonify({"error": "command expired"}), 409

        responded_at = now()
        response_json = json.dumps(
            response_data, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        command_status = "acked" if status == "success" else "failed"
        dry_run = status == "success" and detail == "dry_run"
        decision_status = "dry_run" if dry_run else "executed" if status == "success" else "failed"
        db.execute(
            """UPDATE pending_commands SET status=?,response_json=?,responded_at=?
               WHERE id=? AND status='pending'""",
            (command_status, response_json, responded_at, command_id),
        )
        db.execute(
            "UPDATE decisions SET status=? WHERE decision_id=? AND status='dispatched'",
            (decision_status, command["decision_id"]),
        )
        db.execute(
            "UPDATE executed_decisions SET outcome=? WHERE decision_id=?",
            (decision_status, command["decision_id"]),
        )
        db.execute(
            """INSERT INTO response_actions
               (action,target,description,status,timestamp,triggered_by)
               VALUES (?,?,?,?,?,?)""",
            (
                command["action"], json.loads(command["params_json"]).get("ip", command["params_json"]),
                f"Agent {status}: {detail} ({duration_ms:g} ms)",
                "dry_run" if dry_run else "completed" if status == "success" else "failed",
                responded_at, f"agent:{agent['id']}",
            ),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        logger.exception("Unable to persist response for command %s", command_id)
        return jsonify({"error": "command response persistence failed"}), 503
    finally:
        db.close()

    result = {
        "command_id": command_id,
        "decision_id": command["decision_id"],
        "status": command_status,
        "action": command["action"],
        "detail": detail,
    }
    broadcast("command_result", result, tenant_id=agent["tenant_id"])
    return jsonify({"status": command_status})


# ── Agent ingestion ───────────────────────────────────────────────────────────
@app.route('/api/agent/data', methods=['POST'])
def agent_data():
    timestamp = request.headers.get("X-AEGIS-Timestamp", "")
    event_id = request.headers.get("X-AEGIS-Event-ID", "").strip()
    supplied_signature = request.headers.get("X-AEGIS-Signature", "").lower()
    if not timestamp.isdecimal() or not event_id or len(event_id) > 128:
        return jsonify({"error": "timestamp and a valid event id are required"}), 400
    if abs(int(time.time()) - int(timestamp)) > AGENT_MAX_SKEW_SECONDS:
        return jsonify({"error": "event timestamp is outside the accepted window"}), 401

    body = request.get_data(cache=True)
    try:
        data = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "request body must be valid JSON"}), 400
    if not isinstance(data, dict) or not isinstance(data.get("hostname"), str) or not data["hostname"].strip():
        return jsonify({"error": "hostname required"}), 400
    tenant_id = data.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_exists(tenant_id):
        return jsonify({"error": "a registered tenant_id is required"}), 400
    secret_name = "AEGIS_AGENT_SECRET_" + "".join(
        character if character.isalnum() else "_" for character in tenant_id.upper()
    )
    tenant_secret = os.environ.get(secret_name, AGENT_SECRET if tenant_id == DEFAULT_TENANT_ID else "")
    if not tenant_secret or len(tenant_secret.encode("utf-8")) < 32:
        return jsonify({"error": "signed ingestion is not configured for this tenant"}), 503
    expected_signature = hmac.new(
        tenant_secret.encode("utf-8"),
        timestamp.encode() + b"." + event_id.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        return jsonify({"error": "invalid event signature"}), 401
    try:
        g.db_path = ensure_tenant_data_db(tenant_id, DB)
    except (OSError, sqlite3.Error, ValueError):
        logger.exception("Unable to initialize tenant data database")
        return jsonify({"error": "tenant database unavailable"}), 500

    payload_hash = hashlib.sha256(body).hexdigest()
    with _ingest_lock:
        existing = qone("SELECT payload_hash,result_json FROM agent_events WHERE event_id=?", (event_id,))
        if existing:
            if existing["payload_hash"] != payload_hash:
                return jsonify({"error": "event id has already been used for a different payload"}), 409
            if existing["result_json"]:
                return jsonify(json.loads(existing["result_json"])), 200
            return jsonify({"error": "event is already being processed"}), 409

        previous = qone("SELECT event_hash FROM agent_events ORDER BY created_at DESC,rowid DESC LIMIT 1")
        previous_hash = previous["event_hash"] if previous else ""
        created_at = now()
        event_hash = hashlib.sha256(
            f"{event_id}.{payload_hash}.{previous_hash}.{created_at}".encode("utf-8")
        ).hexdigest()
        exe(
            """INSERT INTO agent_events
               (event_id,hostname,payload_hash,previous_hash,event_hash,created_at)
               VALUES (?,?,?,?,?,?)""",
            (event_id, data["hostname"], payload_hash, previous_hash, event_hash, created_at),
        )
        try:
            result = ingest_and_analyze(data)
            exe("UPDATE agent_events SET result_json=? WHERE event_id=?",
                (json.dumps(safe_json(result)), event_id))
        except Exception:
            exe("DELETE FROM agent_events WHERE event_id=?", (event_id,))
            logger.exception("Signed event ingestion failed for event %s", event_id)
            raise
    return jsonify(result)

@app.route('/api/agent/collect-now', methods=['POST'])
def collect_now():
    try:
        from agent.collector import AegisAgent
        agent = AegisAgent(hostname="aegis-host-local", tenant_id=g.tenant_id)
        raw = agent.collect()
        raw["tenant_id"] = g.tenant_id
        result = ingest_and_analyze(raw)
        return jsonify({"collected": raw, "result": result})
    except Exception:
        logger.exception("On-demand telemetry collection failed")
        return jsonify({"error": "collection failed"}), 500

@app.route('/api/agent/status')
def agent_status():
    agents = qall(
        """SELECT id,hostname,platform,status,last_heartbeat,version,cpu_usage,
                  events_buffered,
                  CASE WHEN julianday(last_heartbeat)>=julianday('now','-2 minutes')
                       THEN 'online' ELSE 'offline' END AS current_status
           FROM agent_status"""
    )
    for agent in agents:
        agent["status"] = agent.pop("current_status")
    online = sum(1 for agent in agents if agent["status"] == "online")
    offline = len(agents) - online
    telemetry = qone(
        """SELECT COUNT(*) AS c FROM agent_telemetry
           WHERE julianday(timestamp)>=julianday('now','-5 minutes')"""
    )["c"]
    events = qone(
        """SELECT COUNT(*) AS c FROM events
           WHERE julianday(received_at)>=julianday('now','-5 minutes')"""
    )["c"]
    latest = qone(
        "SELECT process_count FROM agent_telemetry ORDER BY id DESC LIMIT 1"
    )
    return jsonify({
        "agents": agents,
        "online": online,
        "offline": offline,
        "warning": 0,
        "collectionRates": {
            "telemetryLast5m": telemetry,
            "signedEventsLast5m": events,
            "latestProcessCount": latest["process_count"] if latest else None,
        },
    })

# ── AI specific ───────────────────────────────────────────────────────────────
@app.route('/api/ai/decisions')
def ai_decisions():
    """Return recent AI decision records with full explanations."""
    limit = request.args.get('limit', 10, type=int)
    rows = qall("SELECT * FROM ai_decisions ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        for k in ['evidence','recommended_actions','model_votes','features','attack_chain']:
            if r.get(k):
                try: r[k] = json.loads(r[k])
                except: pass
    return jsonify(rows)

@app.route('/api/ai/decisions/latest')
def ai_latest():
    row = qone("SELECT * FROM ai_decisions ORDER BY id DESC LIMIT 1")
    if not row: return jsonify({})
    for k in ['evidence','recommended_actions','model_votes','features','attack_chain']:
        if row.get(k):
            try: row[k] = json.loads(row[k])
            except: pass
    return jsonify(row)

@app.route('/api/ai/metrics')
def ai_metrics():
    brain = get_brain()
    s = brain.stats()
    total = qone("SELECT COUNT(*) as c FROM ai_decisions")["c"]
    alerts = qone("SELECT COUNT(*) as c FROM alerts WHERE status='active'")["c"]
    threat_breakdown = qall("SELECT threat_type, COUNT(*) as cnt FROM ai_decisions WHERE threat_type!='normal' GROUP BY threat_type ORDER BY cnt DESC")
    return jsonify({
        "models": s.get("models_loaded",[]),
        "modelCount": len(s.get("models_loaded", [])),
        "totalDecisions": total,
        "activeAlerts": alerts,
        "threatBreakdown": threat_breakdown,
        "featureImportance": [{"feature":k,"importance":round(v,4)} for k,v in (s.get("feature_names") or [])[:8]],
    })

@app.route('/api/ai/anomalies')
def ai_anomalies():
    rows = qall("SELECT * FROM ai_decisions WHERE threat_type!='normal' ORDER BY id DESC LIMIT 5")
    result = []
    for r in rows:
        feats = {}
        try: feats = json.loads(r.get("features") or "{}")
        except: pass
        result.append({
            "text": r["explanation"][:120] if r["explanation"] else r["threat_type"],
            "confidence": f"{int(r['confidence']*100)}%",
            "time": r["timestamp"][11:16] if r["timestamp"] else "",
            "type": r["threat_type"],
            "risk_score": r["risk_score"],
        })
    return jsonify(result)

@app.route('/api/ai/explain')
def ai_explain():
    rows = qall("SELECT * FROM alerts WHERE ai_confidence > 0 ORDER BY id DESC LIMIT 3")
    for r in rows:
        for k in ['ai_evidence','ai_recommended_actions','ai_why_not_normal','ai_model_votes']:
            if r.get(k):
                try: r[k] = json.loads(r[k])
                except: pass
    return jsonify(rows)

@app.route('/api/ai/feedback', methods=['POST'])
def ai_feedback():
    d = request.get_json() or {}
    brain = get_brain()
    result = brain.feedback(
        d.get("hostname",""),
        d.get("decision_id",""),
        d.get("was_correct", True),
        d.get("actual_label"),
    )
    return jsonify(result)

# ── SSE ───────────────────────────────────────────────────────────────────────
@app.route('/api/stream')
def sse():
    q = queue.Queue(maxsize=50)
    tenant_id = g.tenant_id
    db_path = g.db_path
    with _sse_lock: _sse_clients.append((tenant_id, q))
    def gen():
        last_snapshot = _active_alert_snapshot(db_path)
        last_scan = time.monotonic()
        last_heartbeat = last_scan
        yield f"data: {json.dumps({'type':'connected','payload':{'msg':'AEGIS event stream connected'}})}\n\n"
        try:
            while True:
                try:
                    yield q.get(timeout=1)
                except queue.Empty:
                    pass
                current_time = time.monotonic()
                if current_time - last_scan >= 2:
                    try:
                        snapshot = _active_alert_snapshot(db_path)
                    except sqlite3.Error:
                        logger.exception("Unable to inspect tenant alert state for SSE")
                        yield f"data: {json.dumps({'type':'stream_error','payload':{'message':'alert state unavailable'}})}\n\n"
                        return
                    if snapshot != last_snapshot:
                        last_snapshot = snapshot
                        yield f"data: {json.dumps({'type':'database_update','payload':{}})}\n\n"
                    last_scan = current_time
                if current_time - last_heartbeat >= 20:
                    yield f"data: {json.dumps({'type':'heartbeat','ts':now()})}\n\n"
                    last_heartbeat = current_time
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove((tenant_id, q))
                except ValueError:
                    pass
    return Response(gen(), mimetype='text/event-stream',
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route('/api/dashboard/summary')
def dashboard():
    active_by_severity = qall(
        "SELECT severity,COUNT(*) AS count FROM alerts WHERE status='active' GROUP BY severity"
    )
    counts = {row["severity"]: row["count"] for row in active_by_severity}
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    active_alerts = sum(counts.values())
    total_threats = critical + high
    assets = qone("SELECT COUNT(*) AS c FROM assets")["c"]
    observations = (
        qone("SELECT COUNT(*) AS c FROM events")["c"]
        + qone("SELECT COUNT(*) AS c FROM agent_telemetry")["c"]
    )
    silent_assets = qone(
        """SELECT COUNT(*) AS c FROM assets
           WHERE last_seen IS NULL OR julianday(last_seen)<julianday('now','-10 minutes')"""
    )["c"]
    score = (
        max(0, min(100, 100 - critical * 10 - high * 5 - silent_assets * 3))
        if observations else None
    )
    level = (
        "NO TELEMETRY" if score is None
        else "LOW RISK" if score >= 80
        else "MEDIUM RISK" if score >= 55
        else "HIGH RISK"
    )
    events_1h = (
        qone(
            "SELECT COUNT(*) AS c FROM events WHERE event_timestamp >= ?",
            (int(time.time()) - 3600,),
        )["c"]
        + qone(
            """SELECT COUNT(*) AS c FROM agent_telemetry
               WHERE julianday(timestamp)>=julianday('now','-1 hour')"""
        )["c"]
    )
    blocked_today = qone(
        "SELECT COUNT(*) AS c FROM blocked_ips WHERE date(blocked_at)=date('now')"
    )["c"]
    return jsonify({
        "securityScore": score,
        "scoreLevel": level,
        "scoreColor": (
            "#556880" if score is None
            else "#00d465" if score >= 80
            else "#f5a020" if score >= 55
            else "#ff3f50"
        ),
        "activeThreats": total_threats,
        "activeAlerts": active_alerts,
        "assetsMonitored": assets,
        "eventsPerHour": events_1h,
        "blockedToday": blocked_today,
    })

# ── Alerts ────────────────────────────────────────────────────────────────────
@app.route('/api/alerts/recent')
def alerts_recent():
    n = request.args.get('limit',5,type=int)
    if n is None:
        n = 5
    rows = qall(
        """SELECT id,severity,title,description,source,timestamp,status,alert_type,
                  ai_confidence,ai_risk_score,event_id,decision_id
           FROM alerts WHERE status='active'
           ORDER BY timestamp DESC LIMIT ?""",
        (max(1, min(n, 50)),),
    )
    return jsonify(rows)

@app.route('/api/alerts/all')
def alerts_all():
    sev=request.args.get('severity',''); st=request.args.get('status','active')
    where=["status=?"]; params=[st]
    if sev: where.append("severity=?"); params.append(sev)
    params.append(200)
    rows=qall(f"SELECT id,severity,title,description,source,timestamp,status,alert_type,ai_confidence,ai_risk_score,ai_explanation,ai_evidence,ai_recommended_actions,ai_why_not_normal FROM alerts WHERE {' AND '.join(where)} ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, timestamp DESC LIMIT ?", params)
    for r in rows:
        for k in ['ai_evidence','ai_recommended_actions','ai_why_not_normal']:
            if r.get(k):
                try: r[k]=json.loads(r[k])
                except: pass
    return jsonify(rows)

@app.route('/api/alerts/counts')
def alert_counts():
    counts = {}
    for s in ['critical','high','medium','low']:
        counts[s]=qone(
            "SELECT COUNT(*) as c FROM alerts WHERE severity=? AND status='active'",
            (s,),
        )["c"]
    return jsonify(counts)

@app.route('/api/alerts/<int:aid>/acknowledge', methods=['PUT'])
def ack_alert(aid):
    exe("UPDATE alerts SET status='acknowledged' WHERE id=?",(aid,))
    audit("alert_acknowledged",f"alert#{aid}","Acked by admin","admin")
    broadcast("alert_update",{"id":aid,"status":"acknowledged"})
    return jsonify({"success":True})

@app.route('/api/alerts/<int:aid>/resolve', methods=['PUT'])
def resolve_alert(aid):
    exe("UPDATE alerts SET status='resolved' WHERE id=?",(aid,))
    audit("alert_resolved",f"alert#{aid}","Resolved by admin","admin")
    broadcast("alert_update",{"id":aid,"status":"resolved"})
    return jsonify({"success":True})

# ── Assets ────────────────────────────────────────────────────────────────────
@app.route('/api/assets/all')
def assets_all():
    return jsonify(qall("SELECT * FROM assets ORDER BY CASE risk_level WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"))

@app.route('/api/assets/risky')
def assets_risky():
    return jsonify(qall("SELECT id,hostname as name,platform as type,os_version as os,risk_level,vulnerabilities FROM assets ORDER BY CASE risk_level WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END LIMIT 6"))

@app.route('/api/assets/counts')
def asset_counts():
    total=qone("SELECT COUNT(*) as c FROM assets")["c"]
    online=qone(
        """SELECT COUNT(*) AS c FROM assets
           WHERE julianday(last_seen)>=julianday('now','-2 minutes')"""
    )["c"]
    high=qone("SELECT COUNT(*) as c FROM assets WHERE risk_level='high'")["c"]
    iso=qone("SELECT COUNT(*) as c FROM assets WHERE status='isolated'")["c"]
    return jsonify({"total":total,"online":online,"high_risk":high,"isolated":iso})

@app.route('/api/assets/<int:aid>')
def asset_detail(aid):
    r=qone("SELECT * FROM assets WHERE id=?",(aid,))
    if not r: return jsonify({"error":"not found"}),404
    return jsonify(r)

# ── Live system ───────────────────────────────────────────────────────────────
@app.route('/api/live/system')
def live_system():
    try:
        from agent.collector import AegisAgent
        data = AegisAgent(hostname="aegis-host").collect()
        return jsonify({"cpu":data["cpu_percent"],"memory":data["memory_percent"],
                        "disk":data["disk_percent"],"users":data["logged_in_users"],
                        "procs":data["process_count"],"ports":len(data["open_ports"]),
                        "open_ports":data["open_ports"],"net_sent":data["bytes_sent_mb"],
                        "net_recv":data["bytes_recv_mb"],"platform":data["platform"],
                        "hostname":data["hostname"],"suspicious":data["suspicious_procs"],
                        "cpu_count":data["cpu_count"]})
    except Exception:
        logger.exception("Unable to collect live system telemetry")
        return jsonify({"error":"live system telemetry is unavailable"}), 503

@app.route('/api/live/telemetry-history')
def telemetry_hist():
    rows=qall("SELECT * FROM agent_telemetry ORDER BY id DESC LIMIT 20")
    rows.reverse()
    return jsonify(rows)

# ── Response / Actions ────────────────────────────────────────────────────────
@app.route('/api/approvals')
def list_approvals():
    if g.principal["role"] not in {"super_admin", "security_admin"}:
        return jsonify({"error": "insufficient role"}), 403
    db = get_db()
    try:
        rows = db.execute(
            """SELECT id,decision_id,action,target,reason,required_role,status,
                      created_at,expires_at
               FROM approval_requests WHERE status='pending' AND expires_at>?
               ORDER BY created_at""",
            (time.time(),),
        ).fetchall()
        return jsonify([dict(row) for row in rows])
    finally:
        db.close()


@app.route('/api/approvals/<decision_id>/approve', methods=['PUT'])
def approve_decision(decision_id):
    if g.principal["role"] not in {"super_admin", "security_admin"}:
        return jsonify({"error": "insufficient role"}), 403
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        approval = db.execute(
            "SELECT required_role,status,expires_at FROM approval_requests WHERE decision_id=?",
            (decision_id,),
        ).fetchone()
        if not approval:
            db.rollback()
            return jsonify({"error": "approval request not found"}), 404
        if approval["status"] != "pending":
            db.rollback()
            return jsonify({"error": "approval request is no longer pending"}), 409
        if approval["expires_at"] <= time.time():
            db.execute(
                "UPDATE approval_requests SET status='expired' WHERE decision_id=?",
                (decision_id,),
            )
            db.commit()
            return jsonify({"error": "approval request expired"}), 409
        if (
            approval["required_role"] == "security_admin"
            and g.principal["role"] != "security_admin"
            and g.principal["role"] != "super_admin"
        ):
            db.rollback()
            return jsonify({"error": "insufficient role"}), 403
        db.execute(
            """UPDATE approval_requests SET status='approved',approved_at=?,approved_by=?
               WHERE decision_id=? AND status='pending'""",
            (now(), g.principal["id"], decision_id),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        logger.exception("Unable to approve decision %s", decision_id)
        return jsonify({"error": "approval update failed"}), 503
    finally:
        db.close()
    audit("decision_approved", decision_id, "Execution approval recorded")
    return jsonify({"success": True, "status": "approved"})


@app.route('/api/response/actions')
def resp_actions():
    return jsonify(qall("SELECT * FROM response_actions ORDER BY timestamp DESC LIMIT 30"))

@app.route('/api/response/actions/<int:action_id>/approve', methods=['PUT'])
def approve_response_action(action_id):
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        cur = db.execute(
            "UPDATE response_actions SET status='approved' WHERE id=? AND status='pending_approval'",
            (action_id,),
        )
        if cur.rowcount != 1:
            db.rollback()
            action = db.execute("SELECT id FROM response_actions WHERE id=?", (action_id,)).fetchone()
            if not action:
                return jsonify({"error": "not found"}), 404
            return jsonify({"error": "action is not awaiting approval"}), 409
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    audit("response_recommendation_approved", str(action_id), "Approved by operator")
    return jsonify({"success": True, "status": "approved",
                    "message": "Approval recorded; this prototype has no action executor."})

@app.route('/api/response/actions/<int:action_id>/reject', methods=['PUT'])
def reject_response_action(action_id):
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        cur = db.execute(
            "UPDATE response_actions SET status='rejected' WHERE id=? AND status='pending_approval'",
            (action_id,),
        )
        if cur.rowcount != 1:
            db.rollback()
            action = db.execute("SELECT id FROM response_actions WHERE id=?", (action_id,)).fetchone()
            if not action:
                return jsonify({"error": "not found"}), 404
            return jsonify({"error": "action is not awaiting approval"}), 409
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    audit("response_recommendation_rejected", str(action_id), "Rejected by operator")
    return jsonify({"success": True, "status": "rejected"})

@app.route('/api/actions/block-ip', methods=['POST'])
def block_ip():
    d=request.get_json() or {}; ip=d.get("ip","").strip(); reason=d.get("reason","Manual block")
    if not ip: return jsonify({"error":"ip required"}),400
    exe("INSERT OR REPLACE INTO blocked_ips (ip,reason,blocked_at,blocked_by) VALUES (?,?,?,?)",(ip,reason,now(),"admin"))
    exe("INSERT INTO response_actions (action,target,description,timestamp,triggered_by) VALUES (?,?,?,?,?)",("block_ip",ip,f"Blocked: {reason}",now(),"manual"))
    audit("block_ip",ip,reason,"admin")
    broadcast("action_taken",{"action":"block_ip","target":ip})
    return jsonify({"success":True,"message":f"IP {ip} blocked"})

@app.route('/api/actions/isolate-device', methods=['POST'])
def isolate():
    d=request.get_json() or {}; device=d.get("device",""); reason=d.get("reason","Manual")
    exe("UPDATE assets SET status='isolated' WHERE hostname=?",(device,))
    exe("INSERT INTO response_actions (action,target,description,timestamp,triggered_by) VALUES (?,?,?,?,?)",("isolate_device",device,f"Isolated: {reason}",now(),"manual"))
    audit("isolate_device",device,reason,"admin")
    return jsonify({"success":True,"message":f"{device} isolated"})

@app.route('/api/actions/lock-account', methods=['POST'])
def lock_acc():
    d=request.get_json() or {}; username=d.get("username","")
    exe("UPDATE users SET is_flagged=1 WHERE username=?",(username,))
    exe("INSERT INTO response_actions (action,target,description,timestamp,triggered_by) VALUES (?,?,?,?,?)",("lock_account",username,"Account locked",now(),"manual"))
    audit("lock_account",username,"Manual lock","admin")
    return jsonify({"success":True})

@app.route('/api/actions/kill-process', methods=['POST'])
def kill_proc():
    d=request.get_json() or {}; device=d.get("device",""); pid=d.get("pid","")
    exe("INSERT INTO response_actions (action,target,description,timestamp,triggered_by) VALUES (?,?,?,?,?)",("kill_process",f"{device}:PID {pid}","Process terminated",now(),"manual"))
    return jsonify({"success":True})

@app.route('/api/actions/run-scan', methods=['POST'])
def run_scan():
    exe("UPDATE assets SET last_seen=?",(now(),))
    exe("INSERT INTO response_actions (action,target,description,timestamp,triggered_by) VALUES (?,?,?,?,?)",("full_scan","all","Full scan initiated",now(),"manual"))
    audit("run_scan","all","Manual scan","admin")
    broadcast("scan_started",{"msg":"Full AI-powered scan initiated"})
    return jsonify({"success":True})

@app.route('/api/blocked-ips')
def get_blocked(): return jsonify(qall("SELECT * FROM blocked_ips ORDER BY blocked_at DESC"))

@app.route('/api/blocked-ips/<path:ip>', methods=['DELETE'])
def del_blocked(ip):
    exe("DELETE FROM blocked_ips WHERE ip=?",(ip,))
    return jsonify({"success":True})

# ── Playbooks / Analytics / Compliance / etc ──────────────────────────────────
@app.route('/api/playbooks')
def get_playbooks(): return jsonify(qall("SELECT * FROM playbooks ORDER BY is_active DESC"))

@app.route('/api/playbooks/<int:pid>/toggle', methods=['PUT'])
def toggle_pb(pid):
    pb=qone("SELECT is_active,name FROM playbooks WHERE id=?",(pid,))
    if not pb: return jsonify({"error":"not found"}),404
    new=0 if pb["is_active"] else 1
    exe("UPDATE playbooks SET is_active=? WHERE id=?",(new,pid))
    return jsonify({"success":True,"is_active":new})

@app.route('/api/analytics/metrics')
def analytics_metrics():
    threats = qone(
        """SELECT COUNT(*) AS c FROM threat_events
           WHERE julianday(timestamp)>=julianday('now','-7 days')"""
    )["c"]
    block_requests = qone(
        """SELECT COUNT(*) AS c FROM response_actions
           WHERE action='block_ip'
             AND julianday(timestamp)>=julianday('now','-7 days')"""
    )["c"]
    active_alerts = qone(
        "SELECT COUNT(*) AS c FROM alerts WHERE status='active'"
    )["c"]
    observations = (
        qone(
            """SELECT COUNT(*) AS c FROM agent_telemetry
               WHERE julianday(timestamp)>=julianday('now','-24 hours')"""
        )["c"]
        + qone(
            """SELECT COUNT(*) AS c FROM events
               WHERE julianday(received_at)>=julianday('now','-24 hours')"""
        )["c"]
    )
    return jsonify({
        "threats7d": threats,
        "blockRequests7d": block_requests,
        "activeAlerts": active_alerts,
        "observations24h": observations,
    })

@app.route('/api/analytics/timeline')
def timeline():
    hours=max(1,min(request.args.get('hours',24,type=int) or 24,168))
    current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    first_hour = current_hour - timedelta(hours=hours - 1)
    rows = qall(
        """SELECT strftime('%Y-%m-%dT%H:00:00Z',timestamp) AS hour,COUNT(*) AS count
           FROM threat_events WHERE timestamp >= ? GROUP BY hour ORDER BY hour""",
        (first_hour.isoformat() + "Z",),
    )
    counts = {row["hour"]: row["count"] for row in rows}
    return jsonify([
        {
            "hour": (first_hour + timedelta(hours=offset)).isoformat(timespec="minutes") + "Z",
            "count": counts.get(
                (first_hour + timedelta(hours=offset)).strftime("%Y-%m-%dT%H:00:00Z"),
                0,
            ),
        }
        for offset in range(hours)
    ])

@app.route('/api/analytics/heatmap')
def heatmap():
    start = datetime.utcnow() - timedelta(days=7)
    rows = qall(
        """SELECT ((CAST(strftime('%w',timestamp) AS INTEGER)+6)%7) AS day,
                  CAST(strftime('%H',timestamp) AS INTEGER) AS hour,
                  COUNT(*) AS count
           FROM threat_events WHERE timestamp >= ?
           GROUP BY day,hour""",
        (start.isoformat() + "Z",),
    )
    counts = {(row["day"], row["hour"]): row["count"] for row in rows}
    return jsonify([
        {"day": day, "hour": hour, "count": counts.get((day, hour), 0)}
        for day in range(7)
        for hour in range(24)
    ])

@app.route('/api/analytics/attack-sources')
def attack_sources():
    rows=qall(
        """SELECT event_type,COUNT(*) AS count FROM threat_events
           WHERE julianday(timestamp)>=julianday('now','-24 hours')
           GROUP BY event_type ORDER BY count DESC LIMIT 6"""
    )
    total=max(sum(r["count"] for r in rows),1)
    cm={"brute_force":"red","malware":"red","ransomware":"red","exfiltration":"cyan","lateral_movement":"amber","anomalous_login":"blue","port_scan":"purple"}
    return jsonify([{"name":r["event_type"].replace("_"," ").title(),"count":r["count"],"pct":round(r["count"]/total*100),"color":cm.get(r["event_type"],"blue")} for r in rows])

@app.route('/api/analytics/predictive-risk')
def pred_risk():
    return jsonify({
        "available": False,
        "reason": "Predictive breach scoring is not implemented in this prototype.",
    })

@app.route('/api/analytics/daily-threats')
def daily_threats():
    today = datetime.utcnow().date()
    data = []
    first_day = today - timedelta(days=6)
    start = datetime.combine(first_day, datetime.min.time()).isoformat() + "Z"
    rows = qall(
        """SELECT date(timestamp) AS day,COUNT(*) AS count FROM threat_events
           WHERE timestamp >= ? GROUP BY date(timestamp)""",
        (start,),
    )
    counts = {row["day"]: row["count"] for row in rows}
    for offset in range(7):
        day = first_day + timedelta(days=offset)
        data.append({
            "date": day.strftime("%a"),
            "count": counts.get(day.isoformat(), 0),
        })
    return jsonify(data)

@app.route('/api/compliance/status')
def compliance(): return jsonify(qall("SELECT * FROM compliance_frameworks"))

@app.route('/api/compliance/audit-log')
def comp_audit(): return jsonify(qall("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 30"))

@app.route('/api/darkweb/intel')
def darkweb():
    exp=qall("SELECT * FROM darkweb_exposures"); feeds=qall("SELECT * FROM intel_feeds")
    return jsonify({
        "exposures": exp,
        "feeds": feeds,
        "leakedEmails": len(exp),
        "leakedCreds": sum(1 for exposure in exp if exposure["password_hash_exposed"]),
        "intelFeeds": sum(1 for feed in feeds if feed["status"] == "active"),
        "iocRecords": sum(feed["ioc_count"] or 0 for feed in feeds),
    })

@app.route('/api/darkweb/exposures/<int:eid>/remediate', methods=['PUT'])
def rem_exp(eid):
    exe("UPDATE darkweb_exposures SET remediation_status='resolved' WHERE id=?",(eid,))
    return jsonify({"success":True})

@app.route('/api/admin/users')
def admin_users():
    if g.principal["role"] not in {"super_admin", "security_admin"}:
        return jsonify({"error": "insufficient role"}), 403
    return jsonify(list_principals(g.tenant_id))

@app.route('/api/admin/users', methods=['POST'])
def create_user():
    if g.principal["role"] not in {"super_admin", "security_admin"}:
        return jsonify({"error": "insufficient role"}), 403
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    role = data.get("role", "analyst")
    if not isinstance(email, str) or not email.strip() or len(email) > 254:
        return jsonify({"error": "a valid email is required"}), 400
    if not isinstance(password, str) or len(password) < 12:
        return jsonify({"error": "password must contain at least 12 characters"}), 400
    try:
        principal_id = create_principal(g.tenant_id, email, password, role)
        audit("principal_created", email.strip().lower(), role, g.principal["email"])
        return jsonify({"success": True, "id": principal_id}), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "email already exists in this tenant"}), 409

@app.route('/api/admin/users/<uid>', methods=['DELETE'])
def del_user(uid):
    if g.principal["role"] not in {"super_admin", "security_admin"}:
        return jsonify({"error": "insufficient role"}), 403
    if uid == g.principal["id"]:
        return jsonify({"error": "cannot deactivate the current account"}), 409
    if not set_principal_active(uid, g.tenant_id, False):
        return jsonify({"error": "user not found"}), 404
    audit("principal_deactivated", uid, "Account deactivated", g.principal["email"])
    return jsonify({"success": True})

@app.route('/api/notification/channels')
def notif_channels(): return jsonify(qall("SELECT * FROM notification_channels"))

@app.route('/api/notification/channels/<ch>/toggle', methods=['PUT'])
def toggle_ch(ch):
    r=qone("SELECT is_enabled FROM notification_channels WHERE channel_name=?",(ch,))
    if not r: return jsonify({"error":"not found"}),404
    new=0 if r["is_enabled"] else 1
    exe("UPDATE notification_channels SET is_enabled=? WHERE channel_name=?",(new,ch))
    return jsonify({"success":True,"is_enabled":new})

@app.route('/api/threats/critical')
def threats_crit(): return jsonify(qall("SELECT id,severity,title,description,source,timestamp,status,alert_type,ai_confidence FROM alerts WHERE severity='critical' AND status='active' ORDER BY timestamp DESC LIMIT 100"))

@app.route('/api/threats/ai-breakdown')
def ai_breakdown():
    rows = qall(
        """SELECT alert_type AS category,COUNT(*) AS count FROM alerts
           WHERE status='active' AND alert_type IS NOT NULL
           GROUP BY alert_type ORDER BY count DESC LIMIT 10"""
    )
    colors = {
        "brute_force": "red",
        "malware": "red",
        "ransomware": "red",
        "exfiltration": "cyan",
        "lateral_movement": "amber",
        "attack_chain": "purple",
    }
    return jsonify([
        {
            "category": row["category"].replace("_", " ").title(),
            "count": row["count"],
            "color": colors.get(row["category"], "blue"),
        }
        for row in rows
    ])

@app.route('/api/health')
def health():
    return jsonify({"status":"ok","timestamp":now(),"ai_brain":"active",
                    "signed_agent_ingestion":bool(AGENT_SECRET and len(AGENT_SECRET.encode("utf-8")) >= 32),
                    "authentication_configured":bool(os.environ.get("AEGIS_JWT_SECRET")),
                    "audit_chain_valid":verify_audit_chain(),
                    "agent_event_chain_valid":verify_agent_event_chain(),
                    "engines":["feature_engine","isolation_forest","random_forest","gradient_boosting","sequence_detector","decision_engine","xai"]})

@app.route('/api/audit/verify-chain')
def audit_verify():
    return jsonify({"valid": verify_audit_chain()})

@app.route('/api/agent/verify-chain')
def agent_event_verify():
    return jsonify({"valid": verify_agent_event_chain()})

@app.route('/')
def index(): return send_file(os.path.join(ROOT_DIR, "index.html"))

# ── Boot ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()

    print("\n🛡️  AEGIS Autonomous AI Cybersecurity Platform")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("📦  Training AI models (first run — ~10 seconds)...")
    brain = get_brain()
    elapsed = registry.warmup()
    print(f"✅  AI Brain ready: {registry.stats()['models_loaded']}")
    print(f"✅  SSE stream: real-time push to dashboard")
    print(f"✅  Background agent: collecting system data every 20s")
    print(f"✅  Server: http://localhost:5000")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    start_decision_worker()
    start_execution_dispatcher()
    threading.Thread(target=_bg_agent, daemon=True).start()
    host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    port = int(os.environ.get("AEGIS_PORT", "5000"))
    app.run(host=host, port=port, debug=False, threaded=True)
