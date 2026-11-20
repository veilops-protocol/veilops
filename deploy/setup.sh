#!/bin/bash
# VEILOPS install/update on a Linux host with Node 22+, systemd and Caddy (idempotent, zero downtime for other sites).
# Upload /root/veilops-release.tgz (Next.js standalone build) first. Own user, port 3700, no secrets, no data dir.
# Touches no other site: only the veilops.tech / www.veilops.tech Caddy blocks are added/replaced (validate, then reload).
set -e
APP=veilops; PORT=3700; DOMAIN=veilops.tech
id $APP >/dev/null 2>&1 || useradd -r -m -d /opt/$APP -s /usr/sbin/nologin $APP
mkdir -p /opt/$APP/releases /etc/$APP
cat > /etc/$APP/env <<ENV
NODE_ENV=production
PORT=$PORT
HOSTNAME=127.0.0.1
NEXT_TELEMETRY_DISABLED=1
ENV
chmod 644 /etc/$APP/env

REL=/opt/$APP/releases/$(date -u +%Y%m%d-%H%M%S)
mkdir -p $REL && tar xzf /root/$APP-release.tgz -C $REL --no-same-permissions
[ -f $REL/apps/website/server.js ] && [ -d $REL/apps/website/.next/static ] || { echo "bad release tarball"; exit 1; }
chown -R $APP:$APP $REL
ln -sfn $REL /opt/$APP/current.new && mv -T /opt/$APP/current.new /opt/$APP/current
LIVE=$(readlink -f /opt/$APP/current)
for old in $(ls -1d /opt/$APP/releases/2* | sort -r | tail -n +4); do [ "$old" != "$LIVE" ] && rm -rf -- "$old"; done

cat > /etc/systemd/system/$APP.service <<UNIT
[Unit]
Description=VEILOPS website (veilops.tech)
After=network-online.target
[Service]
User=$APP
WorkingDirectory=/opt/$APP/current/apps/website
EnvironmentFile=/etc/$APP/env
ExecStart=/usr/bin/node /opt/$APP/current/apps/website/server.js
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
MemoryMax=512M
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable $APP >/dev/null 2>&1
systemctl restart $APP
for i in $(seq 1 60); do curl -sf 127.0.0.1:$PORT/api/health >/dev/null && break; sleep .25; done
curl -sf 127.0.0.1:$PORT/api/health >/dev/null || { echo "app failed to start"; journalctl -u $APP -n 40 --no-pager; exit 1; }

if ! grep -q "reverse_proxy 127.0.0.1:$PORT" /etc/caddy/Caddyfile; then
  BAK=/root/Caddyfile.bak-$APP-$(date -u +%Y%m%d-%H%M%S); cp /etc/caddy/Caddyfile $BAK
  python3 - $DOMAIN $PORT <<'PY'
import sys,re
d,port=sys.argv[1],sys.argv[2]; p='/etc/caddy/Caddyfile'; s=open(p).read()
blk=f'''{d} {{
	encode gzip zstd
	reverse_proxy 127.0.0.1:{port} {{
		lb_try_duration 10s
		lb_try_interval 200ms
	}}
	header {{
		-Server
		Strict-Transport-Security "max-age=31536000"
	}}
}}

www.{d} {{
	redir https://{d}{{uri}} permanent
}}'''
for name in (d, 'www.'+d):
    s=re.sub(r'(?m)^'+re.escape(name)+r' \{\n(?:\t.*\n|\n)*?\}\n*', '', s)
open(p,'w').write(s.rstrip('\n')+'\n\n'+blk+'\n')
PY
  if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then systemctl reload caddy; else echo "caddy validate failed, restoring"; cp $BAK /etc/caddy/Caddyfile; exit 1; fi
fi
systemctl is-active $APP; echo SETUP-DONE
