# smtp-relay

A high-performance, asynchronous SMTP **proxy and load-balancing relay** written in
Rust. It listens on port 1025 (configurable), accepts mail from an application such
as Mautic, rewrites only the `From` *address*, and multiplexes the message across a
pool of upstream SMTP relays using round-robin, weighted, least-used or failover
selection.

Nothing is ever written to a mailbox. The daemon is a routing multiplexer: parse,
rewrite, choose an upstream, deliver, record.

```
                 ┌──────────────────────────────────────────────┐
                 │                 smtp-relay                   │
 Mautic          │                                              │      smtp.domain1.com
 ───── 1025 ────►│  ESMTP listener → rewrite → selector → queue │────► smtp.domain2.com
                 │        │              │           │          │      smtp.domain3.com
                 │        └──────── metrics / events ┘          │
                 └───────────────────┬──────────────────────────┘
                                     │ :8025
                             dashboard + REST API + /metrics
```

## Quick start

```bash
git clone https://github.com/<you>/smtp-relay.git
cd smtp-relay
chmod +x setup.sh
./setup.sh                 # prompts; Enter keeps defaults
cargo build --release
./target/release/smtp-relay
```

On Windows use `powershell -File setup.ps1` instead of `./setup.sh`.

Press Enter through every prompt and you get **admin / admin**, inbound SMTP
**1025**, dashboard **8025**. Then open `http://127.0.0.1:8025/`, sign in, and
add SMTP providers. New providers default to port **465 / SSL**, From = username,
and MAIL FROM alignment off.

## What it does to a message

| Step | Behaviour |
| --- | --- |
| Parse | Headers are split from the body byte-exactly. MIME boundaries, base64 and quoted-printable payloads, and tracking pixels/links are never re-encoded. |
| Preserve | `Subject`, `To`, `Cc`, `Bcc`, the body, DKIM/ARC signatures and the original display name are kept as-is. |
| `From` | Only the address is replaced with the selected relay's identity. The display name is never overridden (`"Jane from Acme" <noreply@relaydomain.com>`). |
| Envelope | `MAIL FROM` stays the original sender unless that provider has **Align envelope** (SPF) enabled. |
| Signatures | Incoming `DKIM-Signature` / `ARC-*` headers are kept. Optional rewrite flags can still strip them. |
| Trace | `Received` and diagnostic `X-Relay-*` headers are off by default. |

## Features

**Routing**
- `round_robin`, `weighted` (smooth weighted round-robin, no clustering), `least_used`, `failover` (strict priority).
- Sticky routing by sender or recipient domain, so a campaign keeps one identity.
- Per-domain overrides (`gmail.com → relay_node_1`, `*.gov.uk → …`).
- Automatic fallback to the next eligible relay when one rejects the message.

**Reliability**
- Retry queue with exponential backoff, capped attempts and optional disk spool that survives a restart.
- Per-relay circuit breaker that only counts relay-side faults, so one bad recipient never takes a relay out of rotation.
- Periodic connect + `EHLO` + `NOOP` health probes with automatic recovery.
- Per-relay per-minute / hourly / daily quotas (off until you enable them) and concurrency caps.
- Graceful shutdown: the listener stops, in-flight deliveries finish, the spool is left intact.

**Control**
- Activate / deactivate a single relay, all relays, a selected subset, or "only these" (activate the selection and deactivate the rest) — from the dashboard or the API.
- Live routing-strategy switching, config edit-and-save, `SIGHUP`/API reload, per-relay probe and test-send.
- Toggles survive restarts because they are mirrored back into the config file.

**Observability**
- Bundled zero-dependency dashboard: throughput chart, per-relay stats, recent messages, queue inspector, config editor, live updates over SSE.
- Prometheus exposition at `/metrics`, `/healthz` and `/readyz` for orchestrators.
- Structured logging (`text`, `compact` or `json`) with optional daily rolling files.

## Build

Requires a stable Rust toolchain (1.75+).

```bash
cargo build --release
# → target/release/smtp-relay
```

The outbound TLS backend is selectable:

```bash
cargo build --release                                          # native-tls (default)
cargo build --release --no-default-features --features tls-rustls   # pure Rust
```

`tls-rustls` avoids the OpenSSL/SChannel dependency and is usually the better
choice for slim Linux containers.

## Run

```bash
./setup.sh                          # or: smtp-relay --generate-config
$EDITOR config.yaml                 # optional; providers can be added in the UI
smtp-relay --check                  # validate without starting
smtp-relay --probe                  # connect to every relay and report
smtp-relay                          # start the daemon
```

```
OPTIONS
  -c, --config <PATH>        config file (.yaml, .yml, .toml, .json)
      --check                validate the configuration and exit
      --print-config         print the effective config, secrets redacted
      --generate-config [P]  write a starter config (default ./config.yaml)
      --force                let --generate-config overwrite an existing file
      --probe                probe every relay and exit (non-zero if any fail)
  -V, --version / -h, --help
```

The config path is taken from `--config`, then `$SMTP_RELAY_CONFIG`, then
`./config.yaml`, `./config.yml`, `./config.toml`, `./config.json`,
`/etc/smtp-relay/config.yaml`. `RUST_LOG` overrides `logging.level`.

## Configuration

`config.example.yaml` documents every option; the minimum viable file is just a
relay list. The schema from the brief works unchanged:

```yaml
server:
  bind_address: "0.0.0.0:1025"
  hostname: "smtp-proxy.local"
  max_message_size_mb: 25
  timeout_seconds: 30

routing:
  strategy: "weighted"        # round_robin | weighted | least_used | failover

relays:
  - id: "relay_node_1"
    host: "smtp.domain1.com"
    port: 465
    tls: "tls"                # none | starttls | tls | opportunistic
    auth:
      username: "mailer@domain1.com"
      password: "secret_password_1"
    from_same_as_username: true   # From = username; uncheck to set from_address
    align_envelope: false         # true = rewrite MAIL FROM (SPF alignment)
    weight: 40                    # 40% of traffic

  - id: "relay_node_2"
    host: "smtp.domain2.com"
    port: 465
    tls: "tls"
    auth:
      username: "mailer@domain2.com"
      password: "secret_password_2"
    from_same_as_username: false
    from_address: "newsletter@domain2.com"
    weight: 60
```

Sections you will probably touch next:

- `server.submission_mode` — `queue` (accept and spool, highest throughput),
  `direct` (pass the upstream verdict back so Mautic owns the retry), or
  `hybrid` (try inline, fall back to the queue).
- `server.allowed_networks` / `server.require_auth` / `server.auth_users` — do
  not expose the listener without one of these.
- `queue.*` — worker count, capacity, attempt cap and backoff curve.
- `health.*` — probe interval and circuit-breaker thresholds.
- `admin.api_token` — required for any non-loopback API access.

### Mautic

In *Configuration → Email Settings*: mailer transport **Other SMTP Server**,
host = the relay host, port = `1025`, encryption = none, authentication = none
(or the credentials from `server.auth_users` if `require_auth` is on). Leave
Mautic's own from-address and display name as the real sender — the relay
rewrites only the From *address*.

## Dashboard and API

The dashboard is served at `http://127.0.0.1:8025/` and needs no build step or
CDN. `setup.sh` writes `admin.username` / `admin.password` (defaults **admin** /
**admin**). After login the browser keeps an HttpOnly session cookie for 12 hours.
Scripts can still use `Authorization: Bearer <admin.api_token>` (or `?token=`
for `EventSource`). With no password and no token, only loopback clients are
accepted.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz`, `/readyz`, `/metrics` | Liveness, readiness, Prometheus. No token. |
| `GET` | `/api/status` | Everything the overview needs: counters, derived rates, per-minute series. |
| `GET` | `/api/series?minutes=60` | Throughput buckets only. |
| `GET` | `/api/events` | SSE stream of message/relay/queue/config events. |
| `GET`/`POST` | `/api/relays` | List, or add a relay. |
| `GET`/`PUT`/`DELETE` | `/api/relays/{id}` | Inspect, replace, remove. |
| `POST` | `/api/relays/{id}/activate` `…/deactivate` `…/toggle` | Single-relay activation. |
| `POST` | `/api/relays/activate-all`, `/api/relays/deactivate-all` | Bulk activation. |
| `POST` | `/api/relays/bulk` | `{"action":"activate\|deactivate\|exclusive","ids":[…]}`. |
| `POST` | `/api/relays/{id}/probe` | Connect + `EHLO` + `NOOP` now. |
| `POST` | `/api/relays/{id}/test` | `{"to":"you@example.com"}` — send a real test message. |
| `POST` | `/api/relays/{id}/reset-stats` `…/reset-circuit` | Clear counters, close the breaker. |
| `GET`/`PUT` | `/api/routing` | Read or change strategy, sticky mode, fallback, attempt cap. |
| `GET`/`PUT` | `/api/config` | Read (secrets redacted) or replace the whole document. |
| `POST` | `/api/config/reload`, `/api/config/save` | Re-read the file, or write the running config. |
| `GET`/`DELETE` | `/api/messages` | Recent activity (`?limit=`, `?status=`, `?relay=`), or clear it. |
| `GET` | `/api/messages/{id}` | One record. |
| `GET`/`DELETE` | `/api/queue`, `/api/queue/{id}` | Inspect, purge, or drop one message. |
| `POST` | `/api/queue/flush` | Make every queued message due immediately. |

Mutating endpoints persist to the config file by default; add `?persist=false`
to change only the running process. Set `admin.allow_config_write: false` to
forbid writes entirely.

```bash
curl -s localhost:8025/api/status | jq .relays
curl -X POST localhost:8025/api/relays/relay_node_2/deactivate
curl -X POST localhost:8025/api/relays/bulk \
     -H 'content-type: application/json' \
     -d '{"action":"exclusive","ids":["relay_node_1"]}'
curl -X POST localhost:8025/api/relays/relay_node_1/test \
     -H 'content-type: application/json' -d '{"to":"you@example.com"}'
```

## Deployment

### systemd

`./setup.sh` builds the binary, writes `config.yaml`, installs
`/usr/local/bin/smtp-relay`, enables `smtp-relay.service`, and starts it.
You do not need to write a unit file by hand.

```bash
sudo systemctl status smtp-relay
sudo systemctl restart smtp-relay
sudo journalctl -u smtp-relay -f
```

### Docker

```dockerfile
FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --no-default-features --features tls-rustls

FROM debian:stable-slim
RUN adduser --system --group --home /var/lib/smtp-relay smtp-relay \
 && install -d -o smtp-relay -g smtp-relay /var/lib/smtp-relay/spool
COPY --from=build /src/target/release/smtp-relay /usr/local/bin/smtp-relay
USER smtp-relay
WORKDIR /var/lib/smtp-relay
EXPOSE 1025 8025
ENV SMTP_RELAY_CONFIG=/etc/smtp-relay/config.yaml
ENTRYPOINT ["smtp-relay"]
```

```yaml
# docker-compose.yml
services:
  smtp-relay:
    build: .
    ports: ["1025:1025", "8025:8025"]
    volumes:
      - ./config.yaml:/etc/smtp-relay/config.yaml:ro
      - relay-spool:/var/lib/smtp-relay/spool
    environment:
      RUST_LOG: info
    healthcheck:
      test: ["CMD", "smtp-relay", "--check"]
      interval: 30s
    restart: unless-stopped

volumes:
  relay-spool:
```

With `tls-rustls` the image needs no OpenSSL. Bind `admin.bind_address` to
`0.0.0.0:8025` **only** together with `admin.api_token`.

## Operating notes

- **Deactivate vs. circuit breaker.** Operator activation and health are
  independent: a relay you switched off stays off even after it recovers, and a
  relay the breaker tripped comes back on its own once probes succeed.
- **Nothing eligible.** If every relay is off, over quota or tripped, mail is
  deferred with a `4xx` (or spooled, in `queue` mode) — never silently dropped.
  `/readyz` returns `503` in that state.
- **Restart-safe state.** Activation toggles and config edits are written back
  to the config file; queued messages stay on the spool when `queue.persist` is
  on.
- **Config edits.** `GET /api/config` redacts passwords as `__redacted__`;
  echoing that value back on `PUT` keeps the stored secret, so the dashboard can
  edit a config it is not allowed to read.
- **Queue sizing changes** (`workers`, `capacity`, `persist`, `directory`) are
  read at startup; the API reports `restart_required_for_queue_changes` when a
  reload touches them.

## Tests

```bash
cargo test
```

Covers header rewriting byte-for-byte, `DATA` dot-unstuffing and size limits,
command parsing, selection fairness for every strategy, breaker and quota
transitions, queue backoff and recovery, CIDR matching, and API authorisation.

### End-to-end smoke test

`smoke/` holds a self-contained harness: a fake upstream SMTP sink, a matching
config, a Mautic-shaped submitter and an SSE watcher. It needs Python 3 and
nothing else.

```bash
python smoke/fake_upstream.py 3025 smoke/received.eml &   # accepts and dumps mail
smtp-relay --config smoke/config.smoke.yaml &
python smoke/send.py 2525                                 # submit one message
python smoke/watch_events.py 8025 5                        # tail the live event stream
```

`smoke/received.eml` then shows exactly what the upstream saw: `From` address
rewritten to the relay identity with the display name intact, original DKIM/ARC
headers still present, and the multipart body, quoted-printable text and
tracking links unchanged.

## Licence

MIT.
#   s m t p - r e l a y  
 