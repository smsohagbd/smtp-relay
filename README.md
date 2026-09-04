# smtp-relay

**Version 1.0.0** — open-source SMTP relay, SMTP proxy, and outbound load balancer.

Self-hosted on your own server. One inbound SMTP port for every app. Many
upstream SMTP accounts (cPanel, Gmail, Microsoft 365, Amazon SES, SendGrid,
or any host:port login). The dashboard is the control panel.

If you are looking for an SMTP relay app, a mail gateway, or a way to send
through **multiple SMTP providers** without changing your software — this is it.

It is not an inbox. It does not store mailboxes. It only accepts, routes, and
sends.

```
Your app                   smtp-relay                    SMTP providers
CRM, shop, forms           :1025  inbound SMTP           cPanel · SES · Gmail
newsletter, transactional  :8025  web dashboard          Microsoft 365 · any
      ──────────────────►  From rewrite · pick · send  ──────────────►
```

Works with **any program that can send SMTP**: websites, CRMs, ERP, helpdesks,
newsletters, custom scripts. No plugin and no vendor lock-in.

## What it does

- One SMTP endpoint for all of your software (default port **1025**)
- **SMTP load balancing** across a pool of providers (round-robin, weighted,
  least-used, or failover)
- Rewrites only the **From email** to the selected account  
  Display name is kept (`Jane <noreply@your-smtp.com>`)
- Body, tracking links, images, To / Cc / Bcc are unchanged
- Automatic retry if a provider fails; circuit breaker skips a dead account
- Web UI: add, clone, bulk-import, test, pause, or delete providers
- Disk mail log like Postfix/Exim: `/var/log/smtp-relay/maillog`

Your apps never see the real SMTP passwords. They only talk to smtp-relay.

## Install

Linux VPS (Ubuntu / Debian and similar). SSH in, then:

```bash
sudo apt-get update
sudo apt-get install -y git curl
git clone https://github.com/smsohagbd/smtp-relay.git
cd smtp-relay
chmod +x setup.sh
./setup.sh
```

`setup.sh` installs the compiler and Rust if needed, asks four questions,
builds the release binary, and starts `smtp-relay` as a systemd service.

| Prompt | Default (press Enter) |
| --- | --- |
| Admin username | `admin` |
| Admin password | `admin` |
| Inbound SMTP port | `1025` |
| Dashboard port | `8025` |

The first build takes a few minutes. When it finishes:

```
Dashboard : http://YOUR-SERVER-IP:8025/
SMTP      : YOUR-SERVER-IP:1025  user admin
```

Open the dashboard with **http** (not https). Sign in with the user and
password you chose.

Already have a `config.yaml`? When it asks **Overwrite?**, choose **N** to
keep your providers and still upgrade the binary.

## Use it

### 1. Add SMTP providers

Dashboard → **Add SMTP provider** → host, port, username, password →
**Test & save**.

New accounts default to **port 465 / SSL**. If the username is an email, it
is used as the From address. Clone or bulk-import when you have many logins.

### 2. Point your software at the relay

In your app’s “custom SMTP” / “other SMTP server” settings:

| Setting | Value |
| --- | --- |
| Host | server IP — or `127.0.0.1` if the app runs on the **same** machine |
| Port | `1025` |
| Encryption | None |
| Authentication | Login |
| Username / password | same as the dashboard login |

Do not put the upstream Gmail/cPanel host in the app. Put **smtp-relay** there.

Same-server installs should use `127.0.0.1`. Connecting to the public IP from
the host itself often returns “connection refused”.

### 3. Send

The app keeps the display name. smtp-relay sends with the provider identity  
(`Jane <info@your-smtp.com>`).

## Commands

```bash
sudo systemctl status smtp-relay
sudo systemctl restart smtp-relay
sudo journalctl -u smtp-relay -f
sudo tail -f /var/log/smtp-relay/maillog
```

## Upgrade

```bash
cd ~/smtp-relay
git checkout -- setup.sh
git pull
./setup.sh
```

Answer **N** to keep the existing config.

If `git pull` refuses because `setup.sh` changed locally:

```bash
git checkout -- setup.sh
git pull
```

## Files

| Path | What it is |
| --- | --- |
| `/etc/smtp-relay/config.yaml` | Live settings and passwords |
| `/var/log/smtp-relay/maillog` | Mail log |
| `/var/lib/smtp-relay/spool` | Messages waiting to retry |

**Delete deferred / failed / all** in the dashboard removes those log lines.
The retry queue is left alone.

Five failed dashboard logins from one IP lock that IP for 15 minutes.

## Licence

MIT
