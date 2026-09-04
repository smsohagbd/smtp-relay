# smtp-relay

An SMTP **proxy and load balancer**. Your app (Mautic, WordPress, Laravel, a
script) sends mail to this server. smtp-relay rewrites only the `From` *address*,
picks an upstream SMTP provider from a pool, and delivers. It does not store
mailboxes.

```
  Your app                 smtp-relay                      Upstream SMTPs
  (Mautic, …)              :1025 inbound                   smtp.provider1.com
       │                   :8025 dashboard                      │
       └──── AUTH ────────►  rewrite → pick relay → send  ──────┘
```

- Only the From **email** is changed. Display name, body, To/Cc/Bcc, DKIM/ARC stay.
- `MAIL FROM` stays original unless you enable SPF alignment on that provider.
- Dashboard is mobile-friendly. Providers can be added, cloned, bulk-imported, tested.

---

## Install (Linux)

You need a VPS or machine you can SSH into. Then:

```bash
sudo apt-get update && sudo apt-get install -y git curl
git clone https://github.com/smsohagbd/smtp-relay.git
cd smtp-relay
chmod +x setup.sh
./setup.sh
```

`setup.sh` does everything else:

1. Installs the compiler, OpenSSL headers, and **Rust** if they are missing  
2. Asks for admin name, password, SMTP port, web port (Enter = defaults)  
3. Writes `config.yaml` (and `/etc/smtp-relay/config.yaml`)  
4. Builds a release binary  
5. Enables and starts `smtp-relay.service`

**Defaults if you press Enter on every prompt**

| Item | Default |
| --- | --- |
| Dashboard + SMTP username | `admin` |
| Password | `admin` |
| Inbound SMTP port | `1025` |
| Dashboard port | `8025` |

If `config.yaml` already exists it asks before overwriting. Answer `N` to keep your relays and still rebuild the service.

**Windows:** `powershell -File setup.ps1` writes a config only. Build with Rust from [rustup.rs](https://rustup.rs/).

---

## After setup

Open the dashboard (use your server IP and the web port you chose):

```
http://YOUR-SERVER-IP:8025/
```

Sign in with the username/password from setup. Then **Add SMTP provider** (or **Bulk add** / **Clone**).

New providers default to **port 465 / SSL**. If the username is an email, From is filled from it. The connection is tested before save.

Point Mautic (or any mailer) at the **relay**, not at Gmail/SES directly:

| Setting | Value |
| --- | --- |
| Host | your server IP |
| Port | `1025` (or whatever you set) |
| Encryption | none |
| Authentication | yes |
| Username / password | same as dashboard (`admin` / `admin` unless you changed them) |

Leave the app’s display name and From as the real sender. The relay rewrites only the address to the selected upstream identity.

Change the SMTP or dashboard password later in `/etc/smtp-relay/config.yaml`:

```yaml
server:
  require_auth: true
  auth_users:
    - username: "admin"
      password: "new-smtp-password"

admin:
  username: "admin"
  password: "new-dashboard-password"
```

Then `sudo systemctl restart smtp-relay`.

`config.yaml` is not in git (it holds secrets). The copy the service uses is:

`/etc/smtp-relay/config.yaml`

---

## Daily commands

```bash
sudo systemctl status smtp-relay
sudo systemctl restart smtp-relay
sudo journalctl -u smtp-relay -f
```

After `git pull` on the server, run `./setup.sh` again (keep the existing config) so the binary and service update.

---

## What it does to a message

| Step | Behaviour |
| --- | --- |
| Parse | Headers split from the body byte-exactly. HTML, pixels, links, MIME are never re-encoded. |
| Keep | Subject, To, Cc, Bcc, body, display name, incoming DKIM/ARC. |
| From | Only the address becomes the selected relay identity. |
| Envelope | Original `MAIL FROM` unless **Align envelope (SPF)** is on for that provider. |
| Quotas | Per minute / hour / day, off until you enable them on the provider. |

---

## Features

- Strategies: `round_robin`, `weighted`, `least_used`, `failover`
- Sticky routing, per-domain overrides, fallback on failure
- Retry queue + disk spool, circuit breaker, health probes
- Activate / deactivate / clone / bulk-import providers
- Test-before-save, probe, send-test
- Dashboard + REST API + Prometheus `/metrics`

Every option is documented in [`config.example.yaml`](config.example.yaml).

---

## Configuration (optional)

Minimum relay list (you can also add these only from the UI):

```yaml
relays:
  - id: "relay_node_1"
    host: "smtp.domain1.com"
    port: 465
    tls: "tls"                 # none | starttls | tls | opportunistic
    auth:
      username: "mailer@domain1.com"
      password: "secret"
    from_same_as_username: true
    align_envelope: true
    weight: 40
```

**Bulk add** in the dashboard, one line per provider:

```
host:port:user:pass:ssl
host:port:user:pass:ssl:from@domain.com
```

Use `|` instead of `:` if the password contains colons. TLS token: `ssl`, `tls`, `starttls`, `none`.

Config search order: `--config`, `$SMTP_RELAY_CONFIG`, `./config.yaml`, `/etc/smtp-relay/config.yaml`.

```
smtp-relay --check
smtp-relay --print-config
smtp-relay --probe
smtp-relay -c /path/to/config.yaml
```

---

## API (short)

Dashboard login sets a cookie. Scripts can use `Authorization: Bearer <admin.api_token>`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` `/readyz` `/metrics` | Health and Prometheus |
| `GET` | `/api/status` | Overview |
| `GET`/`POST` | `/api/relays` | List or add (add probes first) |
| `POST` | `/api/relays/import` | Bulk add from text |
| `PUT`/`DELETE` | `/api/relays/{id}` | Update or delete |
| `POST` | `/api/relays/{id}/probe` `/test` | Health probe / send test mail |

---

## Docker

```bash
cargo build --release --no-default-features --features tls-rustls
```

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

---

## Tests

```bash
cargo test
```

`smoke/` is a Python harness (fake upstream + submitter). See that folder.

## Licence

MIT.
