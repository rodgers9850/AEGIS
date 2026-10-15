import hashlib
import hmac
import json
import os
import queue
import subprocess
import sqlite3
import tempfile
import time
import unittest
import uuid
from datetime import datetime
from unittest.mock import patch

_temporary_directory = tempfile.TemporaryDirectory()
os.environ["AEGIS_DB_PATH"] = os.path.join(_temporary_directory.name, "test.db")
os.environ["AEGIS_IDENTITY_DB_PATH"] = os.path.join(_temporary_directory.name, "identity.db")
os.environ["AEGIS_AGENT_SECRET"] = "test-secret-that-is-at-least-32-bytes"
os.environ["AEGIS_JWT_SECRET"] = "test-jwt-signing-secret-that-is-at-least-32-bytes"
os.environ["AEGIS_COMMAND_SECRET"] = "test-command-signing-secret-at-least-32-bytes"
os.environ["AEGIS_ADMIN_EMAIL"] = "admin@example.test"
os.environ["AEGIS_ADMIN_PASSWORD"] = "a-long-test-password"

import server
from agent import collector
from agent.collector import consume_nonce, execute_command
from ai_engine.features import extract_features
from services.core import build_command_token, verify_command_token


class ServerBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        server.AGENT_SECRET = os.environ["AEGIS_AGENT_SECRET"]
        server.init_db()
        server.init_identity()

    def setUp(self):
        self.client = server.app.test_client()
        response = self.client.post("/api/auth/login", json={
            "email": "admin@example.test",
            "password": "a-long-test-password",
        })
        self.assertEqual(response.status_code, 200)
        self.auth_headers = {"Authorization": "Bearer " + response.get_json()["accessToken"]}

    def signed_request(self, data, event_id=None, timestamp=None):
        data.setdefault("tenant_id", server.DEFAULT_TENANT_ID)
        body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        event_id = event_id or str(uuid.uuid4())
        timestamp = timestamp or str(int(time.time()))
        message = timestamp.encode() + b"." + event_id.encode() + b"." + body
        signature = hmac.new(server.AGENT_SECRET.encode(), message, hashlib.sha256).hexdigest()
        return self.client.post(
            "/api/agent/data",
            data=body,
            content_type="application/json",
            headers={
                "X-AEGIS-Timestamp": timestamp,
                "X-AEGIS-Event-ID": event_id,
                "X-AEGIS-Signature": signature,
            },
        ), event_id

    def signed_agent_headers(self, agent_id, secret, body=b""):
        timestamp = str(int(time.time()))
        event_id = uuid.uuid4().hex
        signature = hmac.new(
            secret.encode(),
            timestamp.encode() + b"." + event_id.encode() + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        return {
            "X-Agent-Id": agent_id,
            "X-Timestamp": timestamp,
            "X-Event-Id": event_id,
            "X-Signature": signature,
        }

    def create_decision(self, approval_level="none", event_timestamp=None, source_ip="1.2.3.4"):
        agent_id, agent_secret = server.register_agent(
            server.DEFAULT_TENANT_ID, "execution-test-" + uuid.uuid4().hex[:8],
        )
        event_id = uuid.uuid4().hex
        event_timestamp = int(time.time()) if event_timestamp is None else event_timestamp
        payload = {
            "event_type": "auth_failure",
            "failed_logins": 15,
            "hostname": server.get_agent(agent_id)["hostname"],
        }
        if source_ip is not None:
            payload["source_ip"] = source_ip
        payload_json = json.dumps(payload, separators=(",", ":"))
        decision_id = str(uuid.uuid4())
        db = sqlite3.connect(server.DB)
        try:
            db.execute(
                """INSERT INTO events
                   (agent_id,event_id,event_type,payload_json,payload_hash,event_timestamp,
                    prev_hash,event_hash,signature,received_at,processed,decision_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,1,?)""",
                (
                    agent_id, event_id, "auth_failure", payload_json,
                    hashlib.sha256(payload_json.encode()).hexdigest(), event_timestamp,
                    "0" * 64, hashlib.sha256(event_id.encode()).hexdigest(),
                    "test-signature", server.now(), decision_id,
                ),
            )
            db.execute(
                """INSERT INTO decisions
                   (decision_id,event_id,agent_id,event_hash,recommended_action,severity,
                    confidence,reason,created_at,status,required_approval_level)
                   VALUES (?,?,?,?,?,?,?,?,?,'pending',?)""",
                (
                    decision_id, event_id, agent_id,
                    hashlib.sha256(event_id.encode()).hexdigest(), "block_ip", "high",
                    0.9, "test decision", server.now(), approval_level,
                ),
            )
            db.commit()
        finally:
            db.close()
        return agent_id, agent_secret, decision_id, event_id

    def test_signed_ingestion_rejects_invalid_signature(self):
        response = self.client.post(
            "/api/agent/data",
            json={"hostname": "test-host", "tenant_id": server.DEFAULT_TENANT_ID},
            headers={
                "X-AEGIS-Timestamp": str(int(time.time())),
                "X-AEGIS-Event-ID": str(uuid.uuid4()),
                "X-AEGIS-Signature": "0" * 64,
            },
        )
        self.assertEqual(response.status_code, 401)

    def test_signed_ingestion_is_idempotent(self):
        payload = {"hostname": "test-host"}
        with patch.object(server, "ingest_and_analyze", return_value={"hostname": "test-host"}) as ingest:
            first, event_id = self.signed_request(payload)
            second, _ = self.signed_request(payload, event_id=event_id)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.get_json(), second.get_json())
        ingest.assert_called_once_with(payload)
        self.assertTrue(server.verify_agent_event_chain())
        reused, _ = self.signed_request({"hostname": "different-host"}, event_id=event_id)
        self.assertEqual(reused.status_code, 409)

    def test_ai_recommendations_require_approval(self):
        actions = server._response_actions_for("malware", "critical", "test-host")
        self.assertTrue(actions)
        action_id = actions[0]["id"]
        self.assertEqual(
            server.qone("SELECT status FROM response_actions WHERE id=?", (action_id,))["status"],
            "pending_approval",
        )
        approved = self.client.put(f"/api/response/actions/{action_id}/approve", headers=self.auth_headers)
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(
            server.qone("SELECT status FROM response_actions WHERE id=?", (action_id,))["status"],
            "approved",
        )
        self.assertEqual(
            self.client.put(f"/api/response/actions/{action_id}/approve", headers=self.auth_headers).status_code,
            409,
        )

    def test_audit_chain_detects_changes(self):
        server.audit("test", "target", "details")
        self.assertTrue(server.verify_audit_chain())
        server.exe("UPDATE audit_log SET details='modified' WHERE action='test'")
        self.assertFalse(server.verify_audit_chain())

    def test_api_requires_authentication_and_logout_revokes_token(self):
        self.assertEqual(self.client.get("/api/dashboard/summary").status_code, 401)
        self.assertEqual(self.client.post("/api/auth/logout", headers=self.auth_headers).status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard/summary", headers=self.auth_headers).status_code, 401)

    def test_viewer_cannot_mutate_and_cannot_cross_tenant_boundary(self):
        tenant_id = "tenant-isolated-test"
        server.create_tenant(tenant_id, "Isolated Tenant")
        server.ensure_tenant_data_db(tenant_id, server.DB)
        server.create_principal(tenant_id, "viewer@example.test", "another-long-test-password", "viewer")
        server.exe(
            "INSERT INTO assets (hostname,platform,status) VALUES (?,?,?)",
            ("default-only-host", "Windows", "online"),
        )
        viewer = server.app.test_client()
        login = viewer.post("/api/auth/login", json={
            "email": "viewer@example.test",
            "password": "another-long-test-password",
            "tenantId": tenant_id,
        })
        self.assertEqual(login.status_code, 200)
        viewer_headers = {"Authorization": "Bearer " + login.get_json()["accessToken"]}
        self.assertEqual(viewer.get("/api/assets/all", headers=viewer_headers).get_json(), [])
        self.assertEqual(
            viewer.put("/api/alerts/1/resolve", headers=viewer_headers).status_code,
            403,
        )

    def test_login_rejects_invalid_password(self):
        response = self.client.post("/api/auth/login", json={
            "email": "admin@example.test",
            "password": "incorrect-password",
        })
        self.assertEqual(response.status_code, 401)

    def test_feature_extraction_handles_missing_remote_address(self):
        features, _, _ = extract_features({
            "hostname": "network-test-host",
            "network_connections": [{"raddr": None}, {"raddr": "10.0.0.1"}],
        })
        self.assertEqual(len(features), 28)

    def test_auth_failure_sources_require_repeated_single_external_ip(self):
        current_time = datetime.now().replace(microsecond=0)
        timestamp = current_time.strftime("%b %d %H:%M:%S")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as log_file:
            for _ in range(10):
                log_file.write(
                    f"{timestamp} host sshd: Failed password for invalid user "
                    "from 192.0.2.14 port 22 ssh2\n"
                )
            log_file.write(
                f"{timestamp} host sshd: Failed password for invalid user "
                "from 198.51.100.8 port 22 ssh2\n"
            )
            log_path = log_file.name
        try:
            total, sources = collector.recent_auth_failure_sources(
                log_paths=[log_path], current_time=current_time,
            )
        finally:
            os.remove(log_path)
        self.assertEqual(total, 11)
        self.assertEqual(sources, {"192.0.2.14": 10, "198.51.100.8": 1})

    def test_firewall_action_is_disabled_by_default(self):
        with patch.dict(os.environ, {"AEGIS_ENABLE_FIREWALL_ACTIONS": "0"}):
            with patch.object(collector.subprocess, "run") as run:
                self.assertEqual(collector._do_block_ip("192.0.2.14"), "dry_run")
                run.assert_not_called()

    def test_opted_in_firewall_action_uses_idempotent_iptables_rule(self):
        completed = [
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
        ]
        with patch.dict(os.environ, {"AEGIS_ENABLE_FIREWALL_ACTIONS": "1"}):
            with patch.object(collector.platform, "system", return_value="Linux"):
                with patch.object(collector.os, "geteuid", create=True, return_value=0):
                    with patch.object(collector.shutil, "which", return_value="/usr/sbin/iptables"):
                        with patch.object(collector.subprocess, "run", side_effect=completed) as run:
                            self.assertEqual(
                                collector._do_block_ip("192.0.2.14"), "blocked",
                            )
        self.assertEqual(run.call_count, 3)
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["/usr/sbin/iptables", "-A", "INPUT", "-s", "192.0.2.14", "-j", "DROP"],
        )
        self.assertFalse(run.call_args_list[1].kwargs.get("shell", False))

    def test_opted_in_firewall_action_handles_existing_rule_and_safety_failures(self):
        with patch.dict(os.environ, {"AEGIS_ENABLE_FIREWALL_ACTIONS": "1"}):
            with patch.object(collector.platform, "system", return_value="Linux"):
                with patch.object(collector.os, "geteuid", create=True, return_value=0):
                    with patch.object(collector.shutil, "which", return_value="/usr/sbin/iptables"):
                        with patch.object(
                            collector.subprocess, "run",
                            return_value=subprocess.CompletedProcess([], 0),
                        ) as run:
                            self.assertEqual(
                                collector._do_block_ip("192.0.2.14"), "already_blocked",
                            )
                        run.assert_called_once()
            with patch.object(collector.platform, "system", return_value="Windows"):
                with self.assertRaises(collector.CommandExecutionError) as error:
                    collector._do_block_ip("192.0.2.14")
                self.assertEqual(error.exception.detail, "firewall_unsupported_platform")
            with patch.object(collector.platform, "system", return_value="Linux"):
                with patch.object(collector.os, "geteuid", create=True, return_value=1000):
                    with self.assertRaises(collector.CommandExecutionError) as error:
                        collector._do_block_ip("192.0.2.14")
                    self.assertEqual(error.exception.detail, "firewall_permission_denied")
                with patch.object(collector.os, "geteuid", create=True, return_value=0):
                    with patch.object(collector.shutil, "which", return_value=None):
                        with self.assertRaises(collector.CommandExecutionError) as error:
                            collector._do_block_ip("192.0.2.14")
                        self.assertEqual(error.exception.detail, "firewall_unavailable")

    def test_firewall_command_failure_is_reported(self):
        completed = [
            subprocess.CompletedProcess([], 1),
            subprocess.CompletedProcess([], 1),
        ]
        with patch.dict(os.environ, {"AEGIS_ENABLE_FIREWALL_ACTIONS": "1"}):
            with patch.object(collector.platform, "system", return_value="Linux"):
                with patch.object(collector.os, "geteuid", create=True, return_value=0):
                    with patch.object(collector.shutil, "which", return_value="/usr/sbin/iptables"):
                        with patch.object(collector.subprocess, "run", side_effect=completed):
                            with self.assertRaises(collector.CommandExecutionError) as error:
                                collector._do_block_ip("192.0.2.14")
        self.assertEqual(error.exception.detail, "firewall_command_failed")

    def test_executed_decisions_is_idempotent(self):
        db = sqlite3.connect(server.DB)
        try:
            db.execute(
                """INSERT INTO executed_decisions
                   (decision_id,tenant_id,executed_at,outcome)
                   VALUES (?,?,?,?)""",
                ("decision-idempotency-test", server.DEFAULT_TENANT_ID, "now", "dispatched"),
            )
            db.commit()
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(
                    """INSERT INTO executed_decisions
                       (decision_id,tenant_id,executed_at,outcome)
                       VALUES (?,?,?,?)""",
                    ("decision-idempotency-test", server.DEFAULT_TENANT_ID, "now", "dispatched"),
                )
        finally:
            db.rollback()
            db.close()

    def test_command_token_roundtrip(self):
        token, nonce = build_command_token(
            "agent-1", "block_ip", {"ip": "1.2.3.4"}, time.time(),
        )
        payload = verify_command_token(token)
        self.assertEqual(payload["nonce"], nonce)
        self.assertEqual(payload["agent_id"], "agent-1")
        self.assertEqual(payload["action"], "block_ip")
        self.assertEqual(payload["params"], {"ip": "1.2.3.4"})

    def test_command_token_rejects_tampering(self):
        token, _ = build_command_token(
            "agent-1", "block_ip", {"ip": "1.2.3.4"}, time.time(),
        )
        tampered = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
        with self.assertRaises(ValueError):
            verify_command_token(tampered)

    def test_dispatcher_rejects_stale_decisions(self):
        _, _, decision_id, _ = self.create_decision(
            event_timestamp=int(time.time()) - 60,
        )
        server._dispatch_one(server.DEFAULT_TENANT_ID, decision_id)
        decision = server.qone(
            "SELECT status FROM decisions WHERE decision_id=?", (decision_id,),
        )
        executed = server.qone(
            "SELECT outcome FROM executed_decisions WHERE decision_id=?", (decision_id,),
        )
        command = server.qone(
            "SELECT id FROM pending_commands WHERE decision_id=?", (decision_id,),
        )
        self.assertEqual(decision["status"], "rejected_stale")
        self.assertEqual(executed["outcome"], "stale")
        self.assertIsNone(command)

    def test_dispatcher_waits_for_approval_then_dispatches_once_and_acks_dry_run(self):
        agent_id, agent_secret, decision_id, _ = self.create_decision()
        server.touch_agent(agent_id)
        server._dispatch_one(server.DEFAULT_TENANT_ID, decision_id)
        server._dispatch_one(server.DEFAULT_TENANT_ID, decision_id)
        commands = server.qall(
            "SELECT * FROM pending_commands WHERE decision_id=?", (decision_id,),
        )
        self.assertEqual(len(commands), 1)

        command = commands[0]
        token_payload = verify_command_token(command["token"])
        self.assertEqual(token_payload["agent_id"], agent_id)
        self.assertEqual(token_payload["action"], "block_ip")
        self.assertEqual(token_payload["params"], {"ip": "1.2.3.4"})
        self.assertEqual(token_payload["exp"] - token_payload["iat"], 30)

        poll = self.client.get(
            f"/v1/agent/commands/{agent_id}",
            headers=self.signed_agent_headers(agent_id, agent_secret),
        )
        self.assertEqual(poll.status_code, 200)
        self.assertEqual(len(poll.get_json()["commands"]), 1)
        self.assertEqual(poll.get_json()["commands"][0]["id"], command["id"])

        result = execute_command(
            poll.get_json()["commands"][0],
            agent_id,
            command_secret=os.environ["AEGIS_COMMAND_SECRET"],
            state_db=os.path.join(_temporary_directory.name, uuid.uuid4().hex + ".db"),
        )
        result["command_id"] = command["id"]
        self.assertEqual(result, {
            "status": "success",
            "detail": "dry_run",
            "command_id": command["id"],
            "duration_ms": result["duration_ms"],
        })

        subscriber = queue.Queue()
        server._sse_clients.append((server.DEFAULT_TENANT_ID, subscriber))
        try:
            response_body = json.dumps(
                result, sort_keys=True, separators=(",", ":"),
            ).encode()
            response = self.client.post(
                f"/v1/agent/commands/{command['id']}/response",
                data=response_body,
                content_type="application/json",
                headers=self.signed_agent_headers(agent_id, agent_secret, response_body),
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["status"], "acked")
            event = json.loads(subscriber.get_nowait().removeprefix("data: ").strip())
            self.assertEqual(event["type"], "command_result")
            self.assertEqual(event["payload"]["status"], "acked")
        finally:
            server._sse_clients.remove((server.DEFAULT_TENANT_ID, subscriber))

        stored = server.qone(
            "SELECT status,response_json FROM pending_commands WHERE id=?", (command["id"],),
        )
        decision = server.qone(
            "SELECT status FROM decisions WHERE decision_id=?", (decision_id,),
        )
        action = server.qone(
            "SELECT status,description FROM response_actions WHERE triggered_by=? ORDER BY id DESC LIMIT 1",
            ("agent:" + agent_id,),
        )
        self.assertEqual(stored["status"], "acked")
        self.assertIsNotNone(stored["response_json"])
        self.assertEqual(decision["status"], "dry_run")
        self.assertEqual(action["status"], "dry_run")
        self.assertEqual(
            server.qone(
                "SELECT outcome FROM executed_decisions WHERE decision_id=?", (decision_id,),
            )["outcome"],
            "dry_run",
        )
        self.assertIn("dry_run", action["description"])

    def test_command_response_accepts_real_firewall_outcomes(self):
        response_details = [
            ("success", "blocked"),
            ("success", "already_blocked"),
            ("failed", "firewall_unsupported_platform"),
            ("failed", "firewall_permission_denied"),
            ("failed", "firewall_unavailable"),
            ("failed", "firewall_command_failed"),
        ]
        for status, detail in response_details:
            with self.subTest(status=status, detail=detail):
                agent_id, agent_secret, decision_id, _ = self.create_decision()
                server.touch_agent(agent_id)
                server._dispatch_one(server.DEFAULT_TENANT_ID, decision_id)
                command = server.qone(
                    "SELECT id FROM pending_commands WHERE decision_id=?", (decision_id,),
                )
                self.assertIsNotNone(command)
                response_body = json.dumps({
                    "command_id": command["id"],
                    "status": status,
                    "detail": detail,
                    "duration_ms": 1,
                }, sort_keys=True, separators=(",", ":")).encode()
                response = self.client.post(
                    f"/v1/agent/commands/{command['id']}/response",
                    data=response_body,
                    content_type="application/json",
                    headers=self.signed_agent_headers(agent_id, agent_secret, response_body),
                )
                self.assertEqual(response.status_code, 200)

    def test_dispatcher_creates_approval_request_and_waits_for_approval(self):
        agent_id, _, decision_id, _ = self.create_decision("security_admin")
        server.touch_agent(agent_id)
        server._dispatch_one(server.DEFAULT_TENANT_ID, decision_id)
        self.assertIsNone(server.qone(
            "SELECT id FROM pending_commands WHERE decision_id=?", (decision_id,),
        ))
        approval = server.qone(
            "SELECT status,required_role FROM approval_requests WHERE decision_id=?",
            (decision_id,),
        )
        self.assertEqual(approval["status"], "pending")
        self.assertEqual(approval["required_role"], "security_admin")

        response = self.client.put(
            f"/api/approvals/{decision_id}/approve",
            headers=self.auth_headers,
        )
        self.assertEqual(response.status_code, 200)
        server._dispatch_one(server.DEFAULT_TENANT_ID, decision_id)
        self.assertIsNotNone(server.qone(
            "SELECT id FROM pending_commands WHERE decision_id=?", (decision_id,),
        ))

    def test_dispatcher_leaves_decision_pending_without_online_agent(self):
        _, _, decision_id, _ = self.create_decision()
        server._dispatch_one(server.DEFAULT_TENANT_ID, decision_id)
        decision = server.qone(
            "SELECT status FROM decisions WHERE decision_id=?", (decision_id,),
        )
        self.assertEqual(decision["status"], "pending")
        self.assertIsNone(server.qone(
            "SELECT id FROM pending_commands WHERE decision_id=?", (decision_id,),
        ))

    def test_dispatcher_does_not_spool_missing_or_unsafe_source_ip(self):
        for source_ip in (None, "127.0.0.1", "not-an-ip"):
            _, _, decision_id, _ = self.create_decision(source_ip=source_ip)
            server.touch_agent(server.qone(
                "SELECT agent_id FROM decisions WHERE decision_id=?", (decision_id,),
            )["agent_id"])
            server._dispatch_one(server.DEFAULT_TENANT_ID, decision_id)
            self.assertEqual(
                server.qone(
                    "SELECT status FROM decisions WHERE decision_id=?", (decision_id,),
                )["status"],
                "pending",
            )
            self.assertIsNone(server.qone(
                "SELECT id FROM pending_commands WHERE decision_id=?", (decision_id,),
            ))

    def test_agent_nonce_ledger_is_single_use(self):
        nonce_db = os.path.join(_temporary_directory.name, uuid.uuid4().hex + ".db")
        nonce = uuid.uuid4().hex
        self.assertTrue(consume_nonce(nonce, "agent-test", db_path=nonce_db))
        self.assertFalse(consume_nonce(nonce, "agent-test", db_path=nonce_db))

    def test_agent_rejects_wrong_agent_stale_token_and_nonce_replay(self):
        secret = os.environ["AEGIS_COMMAND_SECRET"]
        state_db = os.path.join(_temporary_directory.name, uuid.uuid4().hex + ".db")
        wrong_agent_token, _ = build_command_token(
            "agent-other", "block_ip", {"ip": "1.2.3.4"}, time.time(),
        )
        wrong_agent = execute_command(
            {"id": "wrong-agent", "token": wrong_agent_token},
            "agent-test", command_secret=secret, state_db=state_db,
        )
        self.assertEqual((wrong_agent["status"], wrong_agent["detail"]), ("failed", "agent_id_mismatch"))

        stale_token, _ = build_command_token(
            "agent-test", "block_ip", {"ip": "1.2.3.4"}, time.time() - 120,
        )
        stale = execute_command(
            {"id": "stale", "token": stale_token},
            "agent-test", command_secret=secret, state_db=state_db,
        )
        self.assertEqual((stale["status"], stale["detail"]), ("failed", "decision_stale"))

        token, _ = build_command_token(
            "agent-test", "block_ip", {"ip": "1.2.3.4"}, time.time(),
        )
        command = {"id": "replay", "token": token}
        first = execute_command(
            command, "agent-test", command_secret=secret, state_db=state_db,
        )
        replay = execute_command(
            command, "agent-test", command_secret=secret, state_db=state_db,
        )
        self.assertEqual((first["status"], first["detail"]), ("success", "dry_run"))
        self.assertEqual((replay["status"], replay["detail"]), ("failed", "nonce_reuse"))

    def test_agent_command_poll_requires_valid_hmac_and_matching_agent(self):
        agent_id, agent_secret = server.register_agent(
            server.DEFAULT_TENANT_ID, "poll-test-" + uuid.uuid4().hex[:8],
        )
        bad = self.client.get(
            f"/v1/agent/commands/{agent_id}",
            headers=self.signed_agent_headers(agent_id, "wrong-agent-secret" * 3),
        )
        self.assertEqual(bad.status_code, 401)
        mismatch = self.client.get(
            "/v1/agent/commands/not-the-agent",
            headers=self.signed_agent_headers(agent_id, agent_secret),
        )
        self.assertEqual(mismatch.status_code, 403)

    def test_empty_tenant_dashboard_and_analytics_reflect_stored_data(self):
        tenant_id = "empty-" + uuid.uuid4().hex[:12]
        tenant_db = os.path.join(_temporary_directory.name, tenant_id + ".db")
        source = sqlite3.connect(server.DB)
        target = sqlite3.connect(tenant_db)
        try:
            schema = source.execute(
                """SELECT sql FROM sqlite_master
                   WHERE sql IS NOT NULL AND type IN ('table','index','trigger')
                   AND name NOT LIKE 'sqlite_%' ORDER BY type='table' DESC"""
            ).fetchall()
            for (statement,) in schema:
                target.execute(statement)
            target.commit()
        finally:
            source.close()
            target.close()

        server.remove_legacy_demo_fixtures(tenant_db)
        server.create_tenant(tenant_id, "Empty tenant")
        server.create_principal(
            tenant_id, tenant_id + "@example.test", "tenant-test-password", "security_admin",
        )
        client = server.app.test_client()
        login = client.post("/api/auth/login", json={
            "email": tenant_id + "@example.test",
            "password": "tenant-test-password",
            "tenantId": tenant_id,
        })
        self.assertEqual(login.status_code, 200)
        headers = {"Authorization": "Bearer " + login.get_json()["accessToken"]}

        try:
            with patch.object(server, "ensure_tenant_data_db", return_value=tenant_db):
                summary = client.get("/api/dashboard/summary", headers=headers).get_json()
                metrics = client.get("/api/analytics/metrics", headers=headers).get_json()
                sources = client.get("/api/analytics/attack-sources", headers=headers).get_json()
                self.assertIsNone(summary["securityScore"])
                self.assertEqual(summary["activeAlerts"], 0)
                self.assertEqual(summary["assetsMonitored"], 0)
                self.assertEqual(metrics, {
                    "threats7d": 0,
                    "blockRequests7d": 0,
                    "activeAlerts": 0,
                    "observations24h": 0,
                })
                self.assertEqual(sources, [])

                before_alert = server._active_alert_snapshot(tenant_db)
                db = sqlite3.connect(tenant_db)
                db.execute(
                    """INSERT INTO assets (hostname,platform,status,last_seen)
                       VALUES (?,?,?,?)""",
                    ("observed-host", "Linux", "online", server.now()),
                )
                db.execute(
                    """INSERT INTO agent_telemetry
                       (hostname,timestamp,cpu_percent,memory_percent,process_count)
                       VALUES (?,?,?,?,?)""",
                    ("observed-host", server.now(), 15, 30, 42),
                )
                db.execute(
                    """INSERT INTO threat_events (timestamp,event_type,source,details,score)
                       VALUES (?,?,?,?,?)""",
                    (server.now(), "malware", "203.0.113.10", "observed", 90),
                )
                db.execute(
                    """INSERT INTO alerts (severity,title,description,source,timestamp,status)
                       VALUES (?,?,?,?,?,?)""",
                    ("critical", "Observed malware", "Stored event", "203.0.113.10",
                     server.now(), "active"),
                )
                db.commit()
                db.close()

                summary = client.get("/api/dashboard/summary", headers=headers).get_json()
                metrics = client.get("/api/analytics/metrics", headers=headers).get_json()
                sources = client.get("/api/analytics/attack-sources", headers=headers).get_json()
                self.assertEqual(summary["activeThreats"], 1)
                self.assertEqual(summary["activeAlerts"], 1)
                self.assertEqual(summary["assetsMonitored"], 1)
                self.assertEqual(summary["eventsPerHour"], 1)
                self.assertEqual(metrics["threats7d"], 1)
                self.assertEqual(metrics["observations24h"], 1)
                self.assertEqual(sources[0]["name"], "Malware")
                self.assertNotEqual(before_alert, server._active_alert_snapshot(tenant_db))
        finally:
            server.delete_tenant(tenant_id)


if __name__ == "__main__":
    unittest.main()
