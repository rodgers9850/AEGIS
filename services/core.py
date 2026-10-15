"""Security primitives and process-local coordination for the AEGIS prototype."""

import base64
import hashlib
import hmac
import json
import math
import os
import queue
import secrets
import threading
import time
from collections import defaultdict, deque


JWT_SECRET = os.environ.get("AEGIS_JWT_SECRET", "")
if JWT_SECRET and len(JWT_SECRET.encode("utf-8")) < 32:
    raise RuntimeError("AEGIS_JWT_SECRET must contain at least 32 bytes")

COMMAND_SECRET = os.environ.get("AEGIS_COMMAND_SECRET", "")
CONTROL_KEY = os.environ.get("AEGIS_CONTROL_KEY", "")
COMMAND_ACTIONS = frozenset({"block_ip"})

if COMMAND_SECRET and len(COMMAND_SECRET.encode("utf-8")) < 32:
    raise RuntimeError("AEGIS_COMMAND_SECRET must contain at least 32 bytes")
if (
    COMMAND_SECRET and JWT_SECRET
    and hmac.compare_digest(COMMAND_SECRET.encode("utf-8"), JWT_SECRET.encode("utf-8"))
):
    raise RuntimeError("AEGIS_COMMAND_SECRET must be different from AEGIS_JWT_SECRET")


def hash_password(password):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260000)
    return "pbkdf2_sha256$260000${}${}".format(
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(derived).decode("ascii").rstrip("="),
    )


def verify_password(password, stored):
    try:
        algorithm, iterations, salt_text, digest_text = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256" or int(iterations) != 260000:
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(actual, expected)
    except (AttributeError, TypeError, ValueError):
        return False


def _b64encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_access_token(user_id, tenant_id, role, ttl=900):
    if not JWT_SECRET:
        raise RuntimeError("AEGIS_JWT_SECRET is not configured")
    now = int(time.time())
    header = _b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64encode(json.dumps({
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_hex(16),
    }, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64encode(signature)}"


def decode_access_token(token):
    if not JWT_SECRET:
        raise ValueError("AEGIS_JWT_SECRET is not configured")
    try:
        header, payload, signature = token.split(".")
        decoded_header = json.loads(_b64decode(header))
        claims = json.loads(_b64decode(payload))
        signing_input = f"{header}.{payload}".encode("ascii")
        expected = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
        if decoded_header != {"alg": "HS256", "typ": "JWT"}:
            raise ValueError("Unsupported token")
        if not hmac.compare_digest(expected, _b64decode(signature)):
            raise ValueError("Invalid signature")
        if not isinstance(claims.get("exp"), int) or claims["exp"] <= int(time.time()):
            raise ValueError("Expired token")
        if not all(isinstance(claims.get(key), str) and claims[key] for key in ("sub", "tenant_id", "role", "jti")):
            raise ValueError("Invalid claims")
        return claims
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid or expired access token") from exc


def build_command_token(agent_id, action, params, decision_timestamp, ttl=30):
    if not COMMAND_SECRET:
        raise RuntimeError("AEGIS_COMMAND_SECRET is not configured")
    if not isinstance(agent_id, str) or not agent_id or len(agent_id) > 128:
        raise ValueError("Invalid command agent identifier")
    if not isinstance(action, str) or action not in COMMAND_ACTIONS:
        raise ValueError("Unsupported command action")
    if not isinstance(params, dict):
        raise ValueError("Command parameters must be an object")
    if (
        isinstance(decision_timestamp, bool)
        or not isinstance(decision_timestamp, (int, float))
        or abs(decision_timestamp) > 2**53
        or not math.isfinite(decision_timestamp)
    ):
        raise ValueError("Invalid decision timestamp")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 30:
        raise ValueError("Command token TTL must be between 1 and 30 seconds")

    now = int(time.time())
    nonce = secrets.token_hex(16)
    payload = {
        "agent_id": agent_id,
        "action": action,
        "params": params,
        "decision_timestamp": decision_timestamp,
        "nonce": nonce,
        "iat": now,
        "exp": now + ttl,
    }
    try:
        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Command parameters must contain JSON values") from exc
    if len(payload_bytes) > 8192:
        raise ValueError("Command token payload is too large")
    header = _b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    encoded_payload = _b64encode(payload_bytes)
    signing_input = f"{header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(
        COMMAND_SECRET.encode("utf-8"), signing_input, hashlib.sha256,
    ).digest()
    return f"{header}.{encoded_payload}.{_b64encode(signature)}", nonce


def verify_command_token(token, secret=None):
    command_secret = COMMAND_SECRET if secret is None else secret
    if not command_secret:
        raise RuntimeError("AEGIS_COMMAND_SECRET is not configured")
    if not isinstance(command_secret, str):
        raise ValueError("AEGIS_COMMAND_SECRET must be text")
    if len(command_secret.encode("utf-8")) < 32:
        raise ValueError("AEGIS_COMMAND_SECRET must contain at least 32 bytes")
    if JWT_SECRET and hmac.compare_digest(
        command_secret.encode("utf-8"), JWT_SECRET.encode("utf-8"),
    ):
        raise ValueError("AEGIS_COMMAND_SECRET must differ from AEGIS_JWT_SECRET")
    try:
        header, encoded_payload, encoded_signature = token.split(".")
        if len(encoded_payload) > 10924:
            raise ValueError("Command token payload is too large")
        decoded_header = json.loads(_b64decode(header))
        payload = json.loads(_b64decode(encoded_payload))
        signing_input = f"{header}.{encoded_payload}".encode("ascii")
        expected_signature = hmac.new(
            command_secret.encode("utf-8"), signing_input, hashlib.sha256,
        ).digest()
        if decoded_header != {"alg": "HS256", "typ": "JWT"}:
            raise ValueError("Unsupported command token")
        if not hmac.compare_digest(expected_signature, _b64decode(encoded_signature)):
            raise ValueError("Invalid command token signature")
        now = int(time.time())
        if (
            not isinstance(payload, dict)
            or not isinstance(payload.get("iat"), int)
            or not isinstance(payload.get("exp"), int)
            or payload["iat"] > now + 30
            or payload["exp"] <= now
            or payload["exp"] <= payload["iat"]
            or payload["exp"] - payload["iat"] > 30
        ):
            raise ValueError("Invalid or expired command token")
        if (
            not isinstance(payload.get("agent_id"), str)
            or not payload["agent_id"]
            or len(payload["agent_id"]) > 128
            or payload.get("action") not in COMMAND_ACTIONS
            or not isinstance(payload.get("params"), dict)
            or isinstance(payload.get("decision_timestamp"), bool)
            or not isinstance(payload.get("decision_timestamp"), (int, float))
            or abs(payload["decision_timestamp"]) > 2**53
            or not math.isfinite(payload["decision_timestamp"])
            or not isinstance(payload.get("nonce"), str)
            or len(payload["nonce"]) != 32
            or any(c not in "0123456789abcdef" for c in payload["nonce"])
        ):
            raise ValueError("Invalid command token claims")
        return payload
    except (AttributeError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid or expired command token") from exc


def sign_event(agent_id, previous_hash, payload, secret, timestamp=None):
    timestamp = int(time.time()) if timestamp is None else int(timestamp)
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    message = f"{previous_hash}:{timestamp}:{canonical_payload}".encode("utf-8")
    return {
        "agent_id": agent_id,
        "timestamp": timestamp,
        "prev_hash": previous_hash,
        "payload": payload,
        "signature": hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest(),
        "event_hash": hashlib.sha256(message).hexdigest(),
    }


def verify_event_signature(event, secret):
    try:
        timestamp = int(event["timestamp"])
        payload = event["payload"]
        previous_hash = event["prev_hash"]
        message = f"{previous_hash}:{timestamp}:{json.dumps(payload, sort_keys=True, separators=(',', ':'))}".encode("utf-8")
        expected_signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        expected_hash = hashlib.sha256(message).hexdigest()
        return (
            hmac.compare_digest(expected_signature, event["signature"])
            and hmac.compare_digest(expected_hash, event["event_hash"])
        )
    except (KeyError, TypeError, ValueError):
        return False


class RedisSimulator:
    """Small, process-local API-compatible subset used only by this prototype."""

    def __init__(self):
        self._values = {}
        self._streams = defaultdict(list)
        self._groups = defaultdict(dict)
        self._sets = defaultdict(set)
        self._sorteds = defaultdict(dict)
        self._subscribers = defaultdict(list)
        self._lock = threading.RLock()

    def get(self, key):
        with self._lock:
            item = self._values.get(key)
            if item is None:
                return None
            value, expires_at = item
            if expires_at is not None and time.time() >= expires_at:
                del self._values[key]
                return None
            return value

    def set(self, key, value):
        with self._lock:
            self._values[key] = (value, None)

    def setex(self, key, ttl, value):
        with self._lock:
            self._values[key] = (value, time.time() + max(0, ttl))

    def delete(self, key):
        with self._lock:
            self._values.pop(key, None)
            return 1

    def exists(self, key):
        return self.get(key) is not None

    def expire(self, key, ttl):
        with self._lock:
            value = self.get(key)
            if value is not None:
                self._values[key] = (value, time.time() + max(0, ttl))

    def incr(self, key):
        with self._lock:
            value = int(self.get(key) or 0) + 1
            self._values[key] = (str(value), None)
            return value

    def xadd(self, key, fields, maxlen=None):
        with self._lock:
            event_id = f"{int(time.time() * 1000)}-{secrets.token_hex(4)}"
            stream = self._streams[key]
            stream.append({"id": event_id, "fields": fields})
            if maxlen and len(stream) > maxlen:
                del stream[:-maxlen]
            return event_id

    def xlen(self, key):
        with self._lock:
            return len(self._streams.get(key, ()))

    def xreadgroup(self, key, group, count=10, filter_fn=None):
        with self._lock:
            last_seen = self._groups[key].get(group, "")
            entries = [item for item in self._streams.get(key, ()) if item["id"] > last_seen]
            if filter_fn:
                entries = [item for item in entries if filter_fn(item)]
            selected = entries[:count]
            if selected:
                self._groups[key][group] = selected[-1]["id"]
            return list(selected)

    def sadd(self, key, *members):
        with self._lock:
            self._sets[key].update(members)

    def sismember(self, key, member):
        with self._lock:
            return member in self._sets.get(key, ())

    def zadd(self, key, mapping):
        with self._lock:
            self._sorteds[key].update(mapping)

    def zrange(self, key, start=0, end=-1):
        with self._lock:
            ordered = sorted(self._sorteds.get(key, {}).items(), key=lambda item: item[1])
            if end == -1:
                return [member for member, _ in ordered[start:]]
            return [member for member, _ in ordered[start:end + 1]]

    def zremrangebyscore(self, key, minimum, maximum):
        with self._lock:
            self._sorteds[key] = {
                member: score for member, score in self._sorteds.get(key, {}).items()
                if not minimum <= score <= maximum
            }

    def hset(self, key, mapping):
        with self._lock:
            current = self.get(key) or {}
            if not isinstance(current, dict):
                current = {}
            current.update(mapping)
            self._values[key] = (current, None)

    def hgetall(self, key):
        value = self.get(key)
        return value if isinstance(value, dict) else {}

    def subscribe(self, *channels):
        subscription = queue.Queue(maxsize=500)
        with self._lock:
            for channel in channels:
                self._subscribers[channel].append(subscription)
        return subscription

    def unsubscribe(self, subscription, *channels):
        with self._lock:
            for channel in channels:
                if subscription in self._subscribers.get(channel, ()):
                    self._subscribers[channel].remove(subscription)

    def publish(self, channel, message):
        with self._lock:
            subscribers = list(self._subscribers.get(channel, ()))
        for subscription in subscribers:
            try:
                subscription.put_nowait(message)
            except queue.Full:
                continue


class ImmutableStore:
    """Append-only hash-linked journal; not WORM storage."""

    def __init__(self, path):
        import sqlite3
        self._path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS audit_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket TEXT NOT NULL,
                entry_key TEXT NOT NULL,
                tenant_id TEXT,
                payload TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                created_at REAL NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_audit_scope ON audit_entries(bucket, tenant_id, id)")

    def append(self, bucket, key, data, tenant_id=None):
        import sqlite3
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
        with self._lock, sqlite3.connect(self._path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1").fetchone()
            previous_hash = row[0] if row else ""
            entry_hash = hashlib.sha256(
                f"{bucket}\0{key}\0{tenant_id or ''}\0{previous_hash}\0{payload}".encode("utf-8")
            ).hexdigest()
            db.execute(
                """INSERT INTO audit_entries
                   (bucket,entry_key,tenant_id,payload,previous_hash,entry_hash,created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (bucket, key, tenant_id, payload, previous_hash, entry_hash, time.time()),
            )
        return entry_hash

    def query(self, bucket, tenant_id=None, since_ts=0, limit=100):
        import sqlite3
        with sqlite3.connect(self._path) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute(
                """SELECT bucket,entry_key,tenant_id,payload,previous_hash,entry_hash,created_at
                   FROM audit_entries
                   WHERE bucket=? AND tenant_id IS ? AND created_at>? ORDER BY id DESC LIMIT ?""",
                (bucket, tenant_id, since_ts, max(1, min(limit, 1000))),
            ).fetchall()
        return [{
            "bucket": row["bucket"],
            "key": row["entry_key"],
            "tenant_id": row["tenant_id"],
            "data": json.loads(row["payload"]),
            "previous_hash": row["previous_hash"],
            "hash": row["entry_hash"],
            "ts": row["created_at"],
        } for row in rows]


redis = RedisSimulator()
immutable = ImmutableStore(os.environ.get(
    "AEGIS_AUDIT_DB_PATH",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit.db"),
))
