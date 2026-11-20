# Deploying veilops.tech

The website (`apps/website`) is a Next.js 16 app. Most pages are prerendered. There are two small server routes:

- `/api/verify` runs proof verification on the server, statelessly.
- `/api/health`

It needs **no database, no secrets and no environment variables** to run. Every variable it reads is optional:

| Variable | Default | Purpose |
|---|---|---|
| `NEXT_PUBLIC_SITE_URL` | `https://veilops.tech` | Canonical URL and Open Graph links |
| `NEXT_PUBLIC_GITHUB_ORG` | `veilops-protocol` | GitHub organization shown on the site |
| `NEXT_PUBLIC_GITHUB_PUBLISHED` | `true` | Set to `false` for a fork whose repositories don't exist yet; hides the GitHub links. |


Pre-flight, from the repo root:

```bash
npm ci && npm run typecheck && npm run lint && npm test && npm run build
```

## Option A: Vercel

1. Fork or push the monorepo to your GitHub account.
2. In Vercel, import the repository with these settings:
   - **Root Directory:** `apps/website`
   - **Framework:** Next.js
   - Install and build commands come from `apps/website/vercel.json`. Install runs `npm ci` at the repo root so the workspaces resolve.
3. Add the domains under **Project → Settings → Domains**: `veilops.tech` and `www.veilops.tech`.
4. At your DNS provider for `veilops.tech`:
   - `A @ 76.76.21.21`
   - `CNAME www cname.vercel-dns.com`
   - Remove any other `A` record for `@`.

The CLI alternative:

```bash
npm i -g vercel
cd apps/website
vercel link
vercel --prod
```

## Option B: your own Node server (systemd + Caddy)

Requires Node 22+.

```bash
# on the server
git clone https://github.com/veilops-protocol/veilops.git /opt/veilops && cd /opt/veilops
npm ci && npm run build
```

`/etc/systemd/system/veilops.service`:

```ini
[Unit]
Description=veilops.tech
After=network.target

[Service]
WorkingDirectory=/opt/veilops/apps/website
ExecStart=/usr/bin/npx next start -p 3700
Environment=NODE_ENV=production
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

Caddy:

```
veilops.tech, www.veilops.tech {
  encode zstd gzip
  reverse_proxy 127.0.0.1:3700 {
    lb_try_duration 10s
  }
}
```

DNS: `A @ <server IP>` and `A www <server IP>`.

For zero-downtime updates, build into a new release directory, then switch a symlink and restart. `lb_try_duration` holds requests while the process restarts.

## After deploying

```bash
curl -s https://veilops.tech/api/health
curl -s https://veilops.tech/api/records | head -c 300
```

Then open `/verify` and run both demos.

## What this deployment does not include

- No blockchain connection.
- No live indexer. The explorer serves the bundled **sample** dataset.
- No wallet.
- No analytics or telemetry.

To regenerate the samples, run `npm run samples` and rebuild.
