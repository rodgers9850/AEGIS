# AEGIS prototype

This repository is a single-process Flask and SQLite prototype. It is not the
multi-service production architecture described in the AEGIS blueprint.

## Run locally

Run the server from this directory with the project's Python dependencies
installed:

```powershell
$env:AEGIS_HOST = "127.0.0.1"
$env:AEGIS_JWT_SECRET = "<random secret, at least 32 bytes>"
$env:AEGIS_ADMIN_EMAIL = "admin@example.test"
$env:AEGIS_ADMIN_PASSWORD = "<first-run password, at least 12 characters>"
python server.py
```

The SQLite database defaults to `aegis3.db` beside `server.py`; trained model
files default to the `models` directory; the identity registry defaults to
`identity.db`. Override those locations with `AEGIS_DB_PATH`,
`AEGIS_IDENTITY_DB_PATH`, and `AEGIS_MODEL_DIR`. The web server binds to
`127.0.0.1` by default; `AEGIS_HOST` and `AEGIS_PORT` can override that.

The first startup creates the default tenant and the initial administrator
only when both `AEGIS_ADMIN_EMAIL` and `AEGIS_ADMIN_PASSWORD` are set. No
default account or password is shipped. Set `AEGIS_JWT_SECRET` to a stable
random secret of at least 32 bytes; it is required for login and token checks.
The dashboard is available at `http://127.0.0.1:5000/`.

External `POST /api/agent/data` ingestion is disabled unless
the appropriate tenant agent secret is configured to a secret of at least 32
bytes. The default tenant uses `AEGIS_AGENT_SECRET`; other tenant IDs use an
environment variable named `AEGIS_AGENT_SECRET_<TENANT_ID>` (uppercase, with
non-alphanumeric characters replaced by underscores). Events must include a
registered `tenant_id` and the agent must send these headers:

- `X-AEGIS-Timestamp`: Unix timestamp in seconds
- `X-AEGIS-Event-ID`: unique identifier for the event
- `X-AEGIS-Signature`: lowercase hex HMAC-SHA256

The signature is calculated over
`timestamp + "." + event_id + "." + exact_request_body`, using the configured
tenant secret. Events outside the `AEGIS_AGENT_MAX_SKEW_SECONDS` window (default 300
seconds) are rejected. Reusing an event ID with the same body returns the
original result; reusing it with a different body is rejected.

The included collector signs and submits telemetry with
`AegisAgent(tenant_id="tenant-acme-001").submit("https://host/api/agent/data")`;
it reads the corresponding tenant secret from the environment unless a secret
is passed explicitly. Plain HTTP is allowed only for localhost.

Run the targeted behavior tests with:

```powershell
python -m unittest discover -s tests -v
```

## Prototype boundaries

- New databases start without sample incidents, assets, users, or dashboard
  metrics. Dashboard and analytics values reflect records actually stored for
  the selected tenant; when data is absent, the UI shows an empty or unavailable
  state rather than fabricated activity.
- On startup, a one-time migration removes known legacy demo fixtures from
  existing tenant databases. It targets specific prototype hostnames, feed and
  playbook names, and other known fixture values; hash-chained audit history is
  retained.
- AI-generated response actions are recommendations. The prototype dispatches
  signed commands to registered agents only after required approval; endpoint
  actions are dry-run unless the firewall opt-in is explicitly enabled.
- Audit entries and accepted event metadata include SHA-256 hash chains for
  tamper detection. SQLite is not immutable/WORM storage; an operator who can
  rewrite the database can also recompute these hashes.
- SQLite and the in-process idempotency lock are suitable only for this
  prototype's single-process deployment. Tenant identity and dashboard data
  are isolated in local SQLite databases, but this is not a hardened
  multi-tenant production boundary.
- Authentication uses short-lived signed bearer tokens, PBKDF2 password
  hashes, and revocation records in SQLite. Provision more tenants through
  the super-admin API; configure a distinct agent secret for every tenant.
- The app still lacks the blueprint's PostgreSQL/Redis services, independent
  planes, WebSocket gateway, and immutable object storage. Do not expose this
  prototype as a production service.

  The execution plane is prototype scaffolding: tenant databases include
  `executed_decisions` and `pending_commands` tables, and
  `services.core` provides short-lived signed command-token primitives. Configure
  `AEGIS_COMMAND_SECRET` to a distinct random secret of at least 32 bytes before
  using those primitives. The secret must not equal `AEGIS_JWT_SECRET`. There is
  now a SQLite-backed dispatcher, signed agent command polling and response
  endpoints, and a security-admin approval API. Approval-required decisions are
  dispatched only after approval, and only to recently seen registered agents. Command tokens and
  agent requests are signed, short-lived, and nonces are consumed in a local
  agent-side SQLite ledger.

  The only supported command is `block_ip`. It is **dry-run by default**: the
  agent logs the requested IP but never invokes a firewall tool. Real execution
  requires `AEGIS_ENABLE_FIREWALL_ACTIONS=1`, Linux, root privileges, and an
  available `iptables` binary for IPv4 or `ip6tables` for IPv6. It appends an
  INPUT DROP rule only after checking that the exact rule is not already
  present. This opt-in can disrupt network access and has no automated rollback;
  use it only on an isolated disposable VM. The real handler was tested with
  mocked subprocess calls in this Windows workspace, not against a live Linux
  kernel.

  A source IP must be present in the signed event and be globally routable. The
  auth-log collector only attaches a source IP when at least ten recent failures
  come from the same address; otherwise the decision remains undispatched.
  Agent polling can be started explicitly with
  `python agent/collector.py --poll-commands --agent-id ... --secret ... --api-base ...`;
  it requires `AEGIS_COMMAND_SECRET` in the agent environment. This prototype
  is not ready for production response.
