# SkillLedger Production Deployment Runbook — `skillledger.in`

This runbook is the step-by-step path to running SkillLedger in production
on a single VPS at the `skillledger.in` domain.

Target: production stack reachable at
- `https://api.skillledger.in` — FastAPI service + Tessera transparency log
- `https://app.skillledger.in` — Next.js dashboard

Total time: **~30 minutes** end-to-end (excludes DNS propagation wait).
Recurring cost: **~$5/month** for the VPS.

---

## Prerequisites

1. A registered domain. You have `skillledger.in`.
2. A VPS with public IPv4. Recommended:
   - **Hetzner CX22** — €4.51/mo, 2 vCPU, 4 GB RAM, Ubuntu 24.04 LTS
   - **Contabo VPS S** — $5.50/mo, 4 vCPU, 8 GB RAM
   - **Hostinger KVM 1** — $4.99/mo, 1 vCPU, 4 GB RAM
   - **DigitalOcean Basic** — $6/mo, 1 vCPU, 1 GB RAM (tight, but works)
3. Root or sudo SSH access to the VPS.
4. A [Resend](https://resend.com) account with `skillledger.in` added as a
   verified sending domain. Free tier (3,000 emails/mo) is plenty for the
   first 100 users.

Optional but recommended:
- A Stripe account (test mode is fine to start) for billing
- A GitHub OAuth app if you want SSO into the dashboard

---

## Step 1 — DNS records (5 min, +~10 min propagation)

In your DNS provider for `skillledger.in`, add:

| Type | Name | Value | TTL |
|---|---|---|---|
| A | `api` | `<VPS-public-IP>` | 600 |
| A | `app` | `<VPS-public-IP>` | 600 |
| A | `@` (or `skillledger.in.`) | `<VPS-public-IP>` | 600 |
| MX | `@` | `feedback-smtp.eu-west-1.amazonses.com` (or Resend's MX) | 600 |
| TXT | `@` | `v=spf1 include:_spf.resend.com ~all` | 600 |
| TXT | `resend._domainkey` | (DKIM value from Resend dashboard) | 600 |
| TXT | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@skillledger.in` | 600 |

Then wait until `dig +short api.skillledger.in` returns your VPS IP.

---

## Step 2 — Provision the VPS (10 min)

SSH to the VPS as `root` (or a sudo user) and run:

```bash
# Update base system
apt update && apt -y upgrade

# Install Docker + Compose v2
curl -fsSL https://get.docker.com | sh
apt -y install git ufw

# Basic firewall: only SSH + HTTP + HTTPS
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Create a non-root user (recommended)
adduser --disabled-password --gecos "" skillledger
usermod -aG docker skillledger
su - skillledger
```

(The remaining commands run as the `skillledger` user.)

---

## Step 3 — Pull the repository and generate secrets (5 min)

```bash
cd ~
git clone https://github.com/skillledger/skillledger.git
cd skillledger

cp .env.example .env

# Generate strong secrets (each command writes one line to .env via sed)
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -base64 32)|" .env
sed -i "s|^SKILLLEDGER_ADMIN_API_KEY=.*|SKILLLEDGER_ADMIN_API_KEY=$(openssl rand -base64 32)|" .env
sed -i "s|^SKILLLEDGER_JWT_SECRET=.*|SKILLLEDGER_JWT_SECRET=$(openssl rand -base64 32)|" .env
sed -i "s|^AUTH_SECRET=.*|AUTH_SECRET=$(openssl rand -base64 32)|" .env

# Generate Ed25519 key for the transparency log
LOGKEY=$(openssl genpkey -algorithm Ed25519 -outform DER | base64 | tr -d '\n')
sed -i "s|^LOG_PRIVATE_KEY=.*|LOG_PRIVATE_KEY=${LOGKEY}|" .env
```

Now manually edit `.env` and set:

```bash
nano .env
```

| Variable | Value |
|---|---|
| `SKILLLEDGER_DOMAIN` | `api.skillledger.in` |
| `DASHBOARD_DOMAIN` | `app.skillledger.in` |
| `SKILLLEDGER_DASHBOARD_URL` | `https://app.skillledger.in` |
| `SKILLLEDGER_CORS_ORIGINS` | `["https://app.skillledger.in"]` |
| `SKILLLEDGER_RESEND_API_KEY` | (paste from Resend dashboard) |
| `AUTH_URL` | `https://app.skillledger.in` |
| `NEXT_PUBLIC_API_URL` | `https://api.skillledger.in` |
| `API_URL` | `https://api.skillledger.in` |

If billing is enabled, also set:

| Variable | Value |
|---|---|
| `SKILLLEDGER_STRIPE_SECRET_KEY` | (Stripe dashboard, sk_test_... or sk_live_...) |
| `SKILLLEDGER_STRIPE_WEBHOOK_SECRET` | (Stripe dashboard, after creating webhook in Step 6) |
| `SKILLLEDGER_STRIPE_PRICE_ID` | (Stripe price ID for pay-as-you-go) |
| `SKILLLEDGER_STRIPE_SEAT_PRICE_ID` | (Stripe price ID for per-seat) |

Save and exit (`Ctrl-O`, `Enter`, `Ctrl-X` in nano).

---

## Step 4 — Bring the stack up (3 min)

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Wait ~60 seconds for Caddy to provision Let's Encrypt certificates. The
first request to each domain triggers cert issuance.

Verify:

```bash
curl -fsSL https://api.skillledger.in/health         # expect: {"status":"ok"}
curl -fsSL https://api.skillledger.in/docs           # expect: Swagger UI
curl -fsSL https://app.skillledger.in/               # expect: dashboard HTML
docker compose logs -f skillledger-service | head
```

If Caddy logs show `failed to obtain certificate`, double-check the DNS
A records have propagated globally (try from a different network or use
`https://dnschecker.org/`).

---

## Step 5 — Create the first publisher and admin (2 min)

```bash
# Read the admin key out of the .env file
ADMIN_KEY=$(grep "^SKILLLEDGER_ADMIN_API_KEY=" .env | cut -d= -f2)

# Create a publisher (your own org)
curl -X POST https://api.skillledger.in/publishers \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"skillledger","contact_email":"me@rishikeshranjan.com"}'

# Generate a publish API key
curl -X POST https://api.skillledger.in/publishers/1/keys \
  -H "Authorization: Bearer $ADMIN_KEY"
# Save the returned raw_key SOMEWHERE SAFE — it is shown exactly once.
```

---

## Step 6 — Stripe webhook (optional, only if billing enabled, 3 min)

In the [Stripe dashboard](https://dashboard.stripe.com/test/webhooks):

1. Click **Add endpoint**.
2. Endpoint URL: `https://api.skillledger.in/billing/webhook`
3. Listen to events: `checkout.session.completed`, `invoice.payment_succeeded`,
   `customer.subscription.updated`, `customer.subscription.deleted`.
4. Reveal the signing secret (`whsec_...`).
5. Paste it into `.env` as `SKILLLEDGER_STRIPE_WEBHOOK_SECRET`.
6. `docker compose restart skillledger-service`.

---

## Step 7 — Configure backups (2 min, but do it before going live)

```bash
mkdir -p ~/backups

# Daily cron - dump Postgres at 03:00, retain 14 days
cat > /tmp/backup.sh <<'BACKUP'
#!/usr/bin/env bash
set -euo pipefail
DATE=$(date +%Y%m%d-%H%M%S)
cd /home/skillledger/skillledger
docker compose exec -T db pg_dump -U skillledger -d skillledger | gzip > /home/skillledger/backups/db-${DATE}.sql.gz
find /home/skillledger/backups -name 'db-*.sql.gz' -mtime +14 -delete
BACKUP
chmod +x /tmp/backup.sh
sudo mv /tmp/backup.sh /usr/local/bin/skillledger-backup.sh
(crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/skillledger-backup.sh") | crontab -
```

For offsite backups, sync `~/backups/` to S3 / Backblaze / Hetzner Storage Box.

---

## Step 8 — Set up GitHub Container Registry image pulls (optional)

If you publish your own images to GHCR instead of building on the box:

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u ranjanrishikesh --password-stdin
```

---

## Operations Cheat Sheet

```bash
# Status
docker compose ps
docker compose logs -f --tail=100 skillledger-service

# Update to latest main
cd ~/skillledger
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# Restart a single service
docker compose restart skillledger-service
docker compose restart skillledger-dashboard
docker compose restart skillledger-log
docker compose restart caddy

# Run Alembic migrations manually
docker compose exec skillledger-service alembic upgrade head

# Open a psql shell
docker compose exec db psql -U skillledger -d skillledger

# Tail Caddy access log
docker compose logs -f caddy

# Renew certificates (Caddy does this automatically; force if needed)
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
```

---

## Troubleshooting

### `502 Bad Gateway` from Caddy

The service is not healthy. Check `docker compose logs skillledger-service`.
Most common cause: DB migrations haven't run yet — the service container
has not finished its startup hook.

### Certificate issuance fails

Caddy needs ports 80 and 443 free and the DNS A records pointing at this
box. If you are behind Cloudflare, set Cloudflare's "SSL/TLS mode" to
**Full (strict)** and disable the orange-cloud proxy on the records during
issuance.

### `429 Too Many Requests` on Let's Encrypt

You hit a Let's Encrypt rate limit. Wait an hour. While debugging, set
Caddy to staging issuer:
```
{
  acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
}
```
Remove that block once issuance works.

### Dashboard shows `NEXT_PUBLIC_API_URL` undefined

`NEXT_PUBLIC_*` vars are baked at build time. Rebuild the dashboard image
after changing them: `docker compose up -d --build skillledger-dashboard`.

### Stripe webhook returns 400

Verify `SKILLLEDGER_STRIPE_WEBHOOK_SECRET` exactly matches the signing
secret shown in the Stripe dashboard for THIS webhook endpoint (each
endpoint has its own secret).

---

## Going Live Checklist

Before announcing publicly:

- [ ] All four DNS records resolve to the correct IP from multiple regions
- [ ] `https://api.skillledger.in/health` returns 200 with a valid cert
- [ ] `https://app.skillledger.in` loads without console errors
- [ ] OTP email arrives within 30 seconds during signup (test with your own email)
- [ ] Backup cron has run at least once and produced a `.sql.gz` file
- [ ] Firewall blocks every port except 22, 80, 443 (`sudo ufw status`)
- [ ] `SKILLLEDGER_ADMIN_API_KEY` is stored in a password manager (NOT only on the VPS)
- [ ] At least one publisher exists and has a working API key
- [ ] If billing is enabled, a test purchase end-to-end completes
- [ ] GitHub repo is public, README's "one-click deploy" buttons work
- [ ] Resend domain is fully verified (SPF, DKIM, DMARC all green)
- [ ] You have tested a `docker compose pull && up -d` upgrade flow once
