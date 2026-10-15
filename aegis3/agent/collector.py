"""
AEGIS Agent — Real System Data Collector
Runs on any device (Windows/Linux/macOS).
Collects live system telemetry and sends to the AEGIS backend.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import platform
import psutil
import re
import socket
import shutil
import sqlite3
import sys
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.core import verify_command_token


logger = logging.getLogger("aegis.agent")
AUTH_FAILURE_PATTERN = re.compile(r"Failed password|authentication failure|Invalid user", re.IGNORECASE)
SYSLOG_TIMESTAMP_PATTERN = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
AUTH_FAILURE_SOURCE_PATTERN = re.compile(r"\bfrom\s+([0-9a-fA-F:.]+)(?:\s|$)", re.IGNORECASE)


class CommandExecutionError(Exception):
    def __init__(self, detail):
        super().__init__(detail)
        self.detail = detail


def recent_auth_failure_sources(window_sec=60, log_paths=None, current_time=None):
    """Return recent auth-failure totals and counts grouped by parsed source IP."""
    if not isinstance(window_sec, int) or window_sec <= 0:
        raise ValueError("window_sec must be a positive integer")
    paths = log_paths or ("/var/log/auth.log", "/var/log/secure")
    now = current_time or datetime.now()
    cutoff = now - timedelta(seconds=window_sec)
    readable_log_found = False
    count = 0
    sources = {}

    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as log_file:
                log_file.seek(0, os.SEEK_END)
                size = log_file.tell()
                log_file.seek(max(0, size - 500_000))
                content = log_file.read().decode("utf-8", errors="replace")
            readable_log_found = True
            for line in content.splitlines():
                if not AUTH_FAILURE_PATTERN.search(line):
                    continue
                match = SYSLOG_TIMESTAMP_PATTERN.match(line)
                if not match:
                    continue
                try:
                    line_time = datetime.strptime(
                        f"{now.year} {match.group(1)}", "%Y %b %d %H:%M:%S"
                    )
                except ValueError:
                    continue
                if line_time > now + timedelta(days=1):
                    line_time = line_time.replace(year=line_time.year - 1)
                if cutoff <= line_time <= now and AUTH_FAILURE_PATTERN.search(line):
                    count += 1
                    source_match = AUTH_FAILURE_SOURCE_PATTERN.search(line)
                    if source_match:
                        try:
                            source_ip = str(ipaddress.ip_address(source_match.group(1)))
                        except ValueError:
                            continue
                        sources[source_ip] = sources.get(source_ip, 0) + 1
        except OSError:
            logger.exception("Cannot read authentication log %s", path)

    if not readable_log_found:
        logger.warning("No readable Linux authentication log found in %s", ", ".join(paths))
    return count, sources


def count_recent_auth_failures(window_sec=60, log_paths=None, current_time=None):
    """Count recent Linux authentication failures from available system logs."""
    count, _ = recent_auth_failure_sources(
        window_sec=window_sec, log_paths=log_paths, current_time=current_time,
    )
    return count


def _agent_state_path(agent_id):
    state_dir = os.environ.get(
        "AEGIS_AGENT_STATE_DIR",
        os.path.join(os.path.expanduser("~"), ".aegis"),
    )
    filename = hashlib.sha256(agent_id.encode("utf-8")).hexdigest() + ".json"
    return os.path.join(state_dir, filename)


def consume_nonce(nonce, agent_id, db_path=None, expires_at=None):
    if (
        not isinstance(nonce, str) or len(nonce) != 32
        or any(character not in "0123456789abcdef" for character in nonce)
        or not isinstance(agent_id, str) or not agent_id
    ):
        return False
    db_path = db_path or _agent_state_path(agent_id) + ".commands.db"
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), mode=0o700, exist_ok=True)
    now_epoch = time.time()
    expiry = expires_at if expires_at is not None else now_epoch + 30
    db = sqlite3.connect(db_path, timeout=10)
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                used_at TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        db.execute("DELETE FROM used_nonces WHERE expires_at<=?", (now_epoch,))
        try:
            db.execute(
                """INSERT INTO used_nonces (nonce,agent_id,used_at,expires_at)
                   VALUES (?,?,?,?)""",
                (nonce, agent_id, datetime.utcnow().isoformat() + "Z", expiry),
            )
            db.commit()
            return True
        except sqlite3.IntegrityError:
            db.rollback()
            return False
    except sqlite3.Error:
        db.rollback()
        raise
    finally:
        db.close()


def _signed_command_request(method, url, agent_id, secret, body=b"", timeout=10):
    timestamp = str(int(time.time()))
    event_id = uuid.uuid4().hex
    signature = hmac.new(
        secret.encode("utf-8"),
        timestamp.encode("ascii") + b"." + event_id.encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "X-Agent-Id": agent_id,
        "X-Timestamp": timestamp,
        "X-Event-Id": event_id,
        "X-Signature": signature,
    }
    if body:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body if method == "POST" else None, headers=headers, method=method)
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _do_block_ip(ip):
    if os.environ.get("AEGIS_ENABLE_FIREWALL_ACTIONS") != "1":
        logger.warning("DRY RUN: would block IP %s; no firewall command was executed", ip)
        return "dry_run"
    if platform.system() != "Linux":
        raise CommandExecutionError("firewall_unsupported_platform")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise CommandExecutionError("firewall_permission_denied")
    iptables_name = "ip6tables" if ":" in ip else "iptables"
    iptables = shutil.which(iptables_name)
    if not iptables:
        raise CommandExecutionError("firewall_unavailable")

    rule = [iptables, "-C", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        check = subprocess.run(rule, capture_output=True, text=True, timeout=5, check=False)
        if check.returncode == 0:
            return "already_blocked"
        if check.returncode != 1:
            raise CommandExecutionError("firewall_command_failed")

        add = subprocess.run(
            [iptables, "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if add.returncode != 0:
            raise CommandExecutionError("firewall_command_failed")

        verify = subprocess.run(rule, capture_output=True, text=True, timeout=5, check=False)
        if verify.returncode != 0:
            raise CommandExecutionError("firewall_command_failed")
    except subprocess.TimeoutExpired as exc:
        logger.error("iptables command timed out for IP %s", ip)
        raise CommandExecutionError("firewall_command_failed") from exc
    except OSError as exc:
        logger.exception("iptables command failed for IP %s", ip)
        raise CommandExecutionError("firewall_command_failed") from exc
    logger.warning("iptables DROP rule added for %s", ip)
    return "blocked"


def execute_command(command, agent_id, command_secret=None, state_db=None):
    started = time.monotonic()
    status = "failed"
    detail = "invalid_command"
    try:
        payload = verify_command_token(command.get("token"), secret=command_secret)
        if payload["agent_id"] != agent_id:
            detail = "agent_id_mismatch"
            raise ValueError(detail)
        age = time.time() - payload["decision_timestamp"]
        if age > 30 or age < -5:
            detail = "decision_stale"
            raise ValueError(detail)
        if not consume_nonce(
            payload["nonce"], agent_id, db_path=state_db, expires_at=payload["exp"],
        ):
            detail = "nonce_reuse"
            raise ValueError(detail)
        if payload["action"] != "block_ip":
            detail = "unsupported_action"
            raise ValueError(detail)
        ip = payload["params"].get("ip")
        try:
            address = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            detail = "invalid_ip"
            raise ValueError(detail) from None
        if not address.is_global:
            detail = "unsafe_ip"
            raise ValueError(detail)
        detail = _do_block_ip(str(address))
        status = "success"
    except CommandExecutionError as exc:
        detail = exc.detail
        logger.error("Command %s failed: %s", command.get("id"), detail)
    except ValueError as exc:
        if str(exc) not in {
            "agent_id_mismatch", "decision_stale", "nonce_reuse",
            "unsupported_action", "invalid_ip", "unsafe_ip",
        }:
            detail = "signature_failed"
        logger.warning("Command %s rejected: %s", command.get("id"), detail)
    return {
        "status": status,
        "detail": detail,
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }


def command_poller(
    agent_id, agent_secret, api_base, command_secret=None,
    interval=0.5, timeout=10, stop_event=None, state_db=None,
):
    if not agent_id or len(agent_secret.encode("utf-8")) < 32:
        raise ValueError("agent_id and an HMAC secret of at least 32 bytes are required")
    command_secret = command_secret or os.environ.get("AEGIS_COMMAND_SECRET", "")
    if len(command_secret.encode("utf-8")) < 32:
        raise ValueError("AEGIS_COMMAND_SECRET must contain at least 32 bytes")
    parsed_url = urlsplit(api_base)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        raise ValueError("api_base must be an absolute HTTP(S) URL")
    if parsed_url.username or parsed_url.password or parsed_url.fragment:
        raise ValueError("api_base must not contain credentials or a fragment")
    if parsed_url.scheme != "https" and parsed_url.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("signed commands may only use HTTP for localhost")

    api_base = api_base.rstrip("/")
    stop_event = stop_event or threading.Event()
    while not stop_event.is_set():
        try:
            response = _signed_command_request(
                "GET", f"{api_base}/v1/agent/commands/{agent_id}",
                agent_id, agent_secret, timeout=timeout,
            )
            commands = response.get("commands")
            if not isinstance(commands, list):
                raise RuntimeError("Command poll response has invalid shape")
            for command in commands:
                if not isinstance(command, dict) or not isinstance(command.get("id"), str):
                    logger.error("Ignoring malformed command response from server")
                    continue
                result = execute_command(
                    command, agent_id, command_secret=command_secret, state_db=state_db,
                )
                result["command_id"] = command["id"]
                body = json.dumps(
                    result, sort_keys=True, separators=(",", ":"), allow_nan=False,
                ).encode("utf-8")
                _signed_command_request(
                    "POST",
                    f"{api_base}/v1/agent/commands/{command['id']}/response",
                    agent_id, agent_secret, body=body, timeout=timeout,
                )
        except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
            logger.warning("Command poll cycle failed: %s", exc)
        stop_event.wait(interval)


def _read_chain_head(path):
    try:
        with open(path, "r", encoding="utf-8") as state_file:
            chain_head = json.load(state_file).get("chain_head")
    except FileNotFoundError:
        return "0" * 64
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read agent chain state: {exc}") from exc
    if (
        not isinstance(chain_head, str)
        or len(chain_head) != 64
        or any(character not in "0123456789abcdef" for character in chain_head)
    ):
        raise RuntimeError("Agent chain state contains an invalid hash")
    return chain_head


def _save_chain_head(path, chain_head):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=directory, delete=False
        ) as state_file:
            temporary_path = state_file.name
            os.chmod(temporary_path, 0o600)
            json.dump({"chain_head": chain_head}, state_file)
            state_file.flush()
            os.fsync(state_file.fileno())
        os.replace(temporary_path, path)
    except OSError:
        if temporary_path and os.path.exists(temporary_path):
            os.remove(temporary_path)
        raise


def run_once(agent_id, hmac_secret, api_base, hostname=None, state_path=None, timeout=10):
    """Send a single signed auth-failure event when the real log count crosses threshold."""
    if not agent_id or len(hmac_secret.encode("utf-8")) < 32:
        raise ValueError("agent_id and an HMAC secret of at least 32 bytes are required")
    failed_logins, source_counts = recent_auth_failure_sources(window_sec=60)
    if failed_logins < 10:
        logger.info("failed_logins=%s; no event sent (threshold is 10)", failed_logins)
        return None

    parsed_url = urlsplit(api_base)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        raise ValueError("api_base must be an absolute HTTP(S) URL")
    if parsed_url.username or parsed_url.password or parsed_url.fragment:
        raise ValueError("api_base must not contain credentials or a fragment")
    if parsed_url.scheme != "https" and parsed_url.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("signed telemetry may only use HTTP for localhost")

    state_path = state_path or _agent_state_path(agent_id)
    prev_hash = _read_chain_head(state_path)
    event_id = str(uuid.uuid4())
    timestamp = str(int(time.time()))
    payload = {
        "event_type": "auth_failure",
        "failed_logins": failed_logins,
        "hostname": hostname or socket.gethostname(),
        "detected_at": datetime.utcnow().isoformat() + "Z",
        "prev_hash": prev_hash,
    }
    source_ip, source_count = max(
        source_counts.items(), key=lambda item: item[1], default=(None, 0),
    )
    if source_count >= 10:
        payload["source_ip"] = source_ip
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    message = timestamp.encode("ascii") + b"." + event_id.encode("ascii") + b"." + body
    signature = hmac.new(hmac_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    endpoint = api_base.rstrip("/") + "/v1/ingest/event"
    request = Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Agent-Id": agent_id,
            "X-Timestamp": timestamp,
            "X-Event-Id": event_id,
            "X-Signature": signature,
        },
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read().decode("utf-8"))
        status_code = response.status
    if status_code in (200, 202) and result.get("event_hash"):
        _save_chain_head(state_path, result["event_hash"])
    else:
        raise RuntimeError(f"Event was not accepted: HTTP {status_code}: {result}")
    logger.info("failed_logins=%s, sent event %s", failed_logins, event_id)
    return result


class AegisAgent:
    """
    Lightweight agent that collects real system telemetry.
    In production: runs as a background service, sends to /api/agent/data.
    In this demo: called directly by the server to collect host machine data.
    """

    def __init__(self, hostname=None, tenant_id=None):
        self.hostname = hostname or socket.gethostname()
        self.tenant_id = tenant_id or os.environ.get("AEGIS_TENANT_ID", "tenant-acme-001")
        self._prev_disk_io = None
        self._prev_net_io  = None

    def collect(self):
        """Collect all system telemetry in one call."""
        return {
            "hostname":          self.hostname,
            "timestamp":         datetime.utcnow().isoformat() + "Z",
            "platform":          platform.system(),
            "platform_version":  platform.version()[:60],

            # Identity
            "logged_in_users":   self._get_users(),
            "failed_logins":     self._get_failed_logins(),

            # Processes
            "processes":         self._get_processes(),
            "process_count":     len(psutil.pids()),
            "suspicious_procs":  self._get_suspicious_procs(),

            # Resources
            "cpu_percent":       psutil.cpu_percent(interval=0.5),
            "cpu_count":         psutil.cpu_count(),
            "memory_percent":    psutil.virtual_memory().percent,
            "memory_total_gb":   round(psutil.virtual_memory().total / 1e9, 1),
            "memory_used_gb":    round(psutil.virtual_memory().used  / 1e9, 1),

            # Disk
            "disk_percent":      self._get_disk_percent(),
            "disk_write_mb":     self._get_disk_write_mb(),

            # Network
            "network_connections": self._get_connections(),
            "open_ports":          self._get_open_ports(),
            "bytes_sent_mb":       self._get_net_sent(),
            "bytes_recv_mb":       self._get_net_recv(),
        }

    def submit(self, api_url, secret=None, event_id=None, timeout=10):
        """Send signed telemetry to the configured AEGIS ingestion endpoint."""
        secret_name = "AEGIS_AGENT_SECRET_" + "".join(
            character if character.isalnum() else "_" for character in self.tenant_id.upper()
        )
        signing_secret = secret or os.environ.get(
            secret_name,
            os.environ.get("AEGIS_AGENT_SECRET", "") if self.tenant_id == "tenant-acme-001" else "",
        )
        if len(signing_secret.encode("utf-8")) < 32:
            raise ValueError("AEGIS agent secret must contain at least 32 bytes")

        parsed_url = urlsplit(api_url)
        if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
            raise ValueError("api_url must be an absolute HTTP(S) URL")
        if parsed_url.username or parsed_url.password or parsed_url.fragment:
            raise ValueError("api_url must not contain credentials or a fragment")
        if parsed_url.scheme != "https" and parsed_url.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValueError("signed telemetry may only use HTTP for localhost")

        event = self.collect()
        event["tenant_id"] = self.tenant_id
        payload = json.dumps(event, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        event_id = event_id or uuid.uuid4().hex
        message = timestamp.encode("ascii") + b"." + event_id.encode("utf-8") + b"." + payload
        signature = hmac.new(signing_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        request = Request(
            api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-AEGIS-Timestamp": timestamp,
                "X-AEGIS-Event-ID": event_id,
                "X-AEGIS-Signature": signature,
            },
            method="POST",
        )
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def _get_users(self):
        try:
            return list({u.name for u in psutil.users()})
        except:
            return []

    def _get_failed_logins(self):
        """Read failed login count from the current Linux auth logs."""
        return count_recent_auth_failures()

    def _get_processes(self):
        procs = []
        try:
            for p in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
                try:
                    procs.append(p.info['name'])
                except:
                    pass
        except:
            pass
        return procs[:50]  # top 50

    def _get_suspicious_procs(self):
        WATCHLIST = {
            "mimikatz","meterpreter","cobaltstrike","psexec","wce.exe",
            "pwdump","nc.exe","ncat","netcat","cryptolocker","wannacry",
            "lazagne","masscan","hydra","john","hashcat","medusa"
        }
        found = []
        try:
            for p in psutil.process_iter(['name']):
                name = (p.info.get('name') or '').lower()
                if any(w in name for w in WATCHLIST):
                    found.append(name)
        except:
            pass
        return found

    def _get_disk_percent(self):
        try:
            return psutil.disk_usage(os.path.abspath(os.sep)).percent
        except:
            return 0

    def _get_disk_write_mb(self):
        try:
            io = psutil.disk_io_counters()
            if self._prev_disk_io is None:
                self._prev_disk_io = io.write_bytes
                return 0
            diff = max(0, io.write_bytes - self._prev_disk_io)
            self._prev_disk_io = io.write_bytes
            return round(diff / 1e6, 2)
        except:
            return 0

    def _get_connections(self):
        conns = []
        try:
            for c in psutil.net_connections(kind='inet')[:30]:
                conns.append({
                    "lport": c.laddr.port if c.laddr else None,
                    "raddr": str(c.raddr.ip) if c.raddr else None,
                    "status": c.status,
                })
        except:
            pass
        return conns

    def _get_open_ports(self):
        ports = set()
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.status == 'LISTEN' and c.laddr:
                    ports.add(c.laddr.port)
        except:
            pass
        return list(ports)[:30]

    def _get_net_sent(self):
        try:
            return round(psutil.net_io_counters().bytes_sent / 1e6, 1)
        except:
            return 0

    def _get_net_recv(self):
        try:
            return round(psutil.net_io_counters().bytes_recv / 1e6, 1)
        except:
            return 0


def main():
    parser = argparse.ArgumentParser(
        description="Send Linux auth-failure events or poll signed AEGIS commands",
    )
    parser.add_argument("--agent-id", default=os.environ.get("AEGIS_AGENT_ID"))
    parser.add_argument("--secret", default=os.environ.get("AEGIS_AGENT_HMAC_SECRET"))
    parser.add_argument("--api-base", default=os.environ.get("AEGIS_API_BASE"))
    parser.add_argument("--state-path", default=None)
    parser.add_argument(
        "--poll-commands",
        action="store_true",
        help="continuously poll for signed dry-run response commands",
    )
    args = parser.parse_args()
    if not args.agent_id or not args.secret or not args.api_base:
        parser.error(
            "provide --agent-id, --secret, and --api-base, or set "
            "AEGIS_AGENT_ID, AEGIS_AGENT_HMAC_SECRET, and AEGIS_API_BASE"
        )
    if args.poll_commands:
        command_poller(args.agent_id, args.secret, args.api_base)
    else:
        run_once(args.agent_id, args.secret, args.api_base, state_path=args.state_path)


if __name__ == "__main__":
    main()
