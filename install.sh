#!/usr/bin/env bash
set -euo pipefail

APP_USER=cyberrssbot
BASE=/opt/cyberrssbot
APP="$BASE/app"
VENV="$BASE/venv"
UNIT=/etc/systemd/system/cyberrssbot.service
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="$SRC/deploy.bundle.enc"

step() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: bash install.sh"
command -v apt-get >/dev/null || die "this script expects Debian or Ubuntu"

step "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-pip git sqlite3 ca-certificates tzdata openssl cron unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF

step "Creating service user $APP_USER"
if ! id "$APP_USER" >/dev/null 2>&1; then
    adduser --system --group --home "$BASE" --shell /usr/sbin/nologin "$APP_USER"
fi
mkdir -p "$APP"

if systemctl is-active --quiet cyberrssbot 2>/dev/null; then
    step "Stopping the running service for the update"
    systemctl stop cyberrssbot
fi

step "Copying code to $APP"
if [ "$SRC" != "$APP" ]; then
    rm -rf "$APP/cyberrssbot"
    cp -a "$SRC/cyberrssbot" "$SRC/requirements.txt" "$APP/"
    for f in README.md LICENSE config.example.yaml .env.example; do
        [ -f "$SRC/$f" ] && cp -a "$SRC/$f" "$APP/"
    done
fi

if [ ! -f "$APP/.env" ] || [ ! -f "$APP/config.yaml" ]; then
    [ -f "$BUNDLE" ] || die "$APP/.env or config.yaml is missing and there is no deploy.bundle.enc to restore them from"
    step "Decrypting deploy.bundle.enc (type the bundle passphrase)"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    ok=0
    for attempt in 1 2 3; do
        read -rsp "Bundle passphrase: " BUNDLE_PASS
        echo
        export BUNDLE_PASS
        if openssl enc -d -aes-256-cbc -pbkdf2 -iter 1000000 -pass env:BUNDLE_PASS \
                -in "$BUNDLE" -out "$tmp/bundle.tgz" 2>/dev/null && tar -tzf "$tmp/bundle.tgz" >/dev/null 2>&1; then
            ok=1
            break
        fi
        echo "Wrong passphrase, try again ($attempt/3)."
    done
    unset BUNDLE_PASS
    [ "$ok" -eq 1 ] || die "could not decrypt the bundle"
    tar --no-same-owner -xzf "$tmp/bundle.tgz" -C "$tmp"
    for f in .env config.yaml; do
        if [ ! -f "$APP/$f" ]; then
            install -m 600 "$tmp/$f" "$APP/$f"
            echo "restored $f"
        fi
    done
    db="$(ls "$tmp"/*.db 2>/dev/null | head -n1 || true)"
    if [ -n "$db" ] && [ ! -f "$APP/$(basename "$db")" ]; then
        install -m 640 "$db" "$APP/$(basename "$db")"
        echo "restored $(basename "$db")"
    fi
    rm -rf "$tmp"
    trap - EXIT
fi
chown -R "$APP_USER:$APP_USER" "$BASE"
chmod 600 "$APP/.env"

step "Setting up the Python environment"
if [ ! -x "$VENV/bin/python" ]; then
    runuser -u "$APP_USER" -- python3 -m venv "$VENV"
fi
runuser -u "$APP_USER" -- "$VENV/bin/pip" install -q --upgrade pip
runuser -u "$APP_USER" -- "$VENV/bin/pip" install -q -r "$APP/requirements.txt"

step "Checking every source once (posts nothing, takes about a minute)"
(cd "$APP" && runuser -u "$APP_USER" -- "$VENV/bin/python" -m cyberrssbot --check) || echo "Some sources failed the check; the service is installed anyway."

write_unit() {
    cat > "$UNIT" <<UNITFILE
[Unit]
Description=CyberRSSBot
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP
ExecStart=$VENV/bin/python -m cyberrssbot
Restart=always
RestartSec=15
Environment=PYTHONUNBUFFERED=1
NoNewPrivileges=true
UNITFILE
    if [ "$1" = "sandboxed" ]; then
        cat >> "$UNIT" <<UNITFILE
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP
UNITFILE
    fi
    cat >> "$UNIT" <<'UNITFILE'

[Install]
WantedBy=multi-user.target
UNITFILE
}

step "Installing the systemd service"
write_unit sandboxed
systemctl daemon-reload
systemctl enable cyberrssbot >/dev/null 2>&1
systemctl restart cyberrssbot
sleep 8
if ! systemctl is-active --quiet cyberrssbot; then
    if [ "$(systemctl show -p ExecMainStatus --value cyberrssbot)" = "226" ]; then
        echo "This container does not allow systemd sandboxing; installing without it."
        write_unit plain
        systemctl daemon-reload
        systemctl restart cyberrssbot
        sleep 8
    fi
fi

step "Journal size limit and daily database backup"
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=200M\n' > /etc/systemd/journald.conf.d/cyberrssbot.conf
systemctl restart systemd-journald || true
DBFILE="$(sed -n 's/^database:[[:space:]]*//p' "$APP/config.yaml" | tr -d '"'"'"' ')"
DBFILE="${DBFILE:-cyberrssbot.db}"
cat > /etc/cron.daily/cyberrssbot-backup <<CRON
#!/bin/sh
set -e
dir=$BASE/backups
mkdir -p "\$dir"
sqlite3 "$APP/$DBFILE" ".backup '\$dir/db-\$(date +%F).db'"
find "\$dir" -name 'db-*.db' -mtime +7 -delete
chown -R $APP_USER:$APP_USER "\$dir"
CRON
chmod 755 /etc/cron.daily/cyberrssbot-backup

step "Done"
systemctl --no-pager --lines=0 status cyberrssbot || true
echo
journalctl -u cyberrssbot -n 15 --no-pager || true
echo
if systemctl is-active --quiet cyberrssbot; then
    echo "The bot is running and will start automatically on boot."
    echo "Logs: journalctl -u cyberrssbot -f     Update: git pull && bash install.sh"
else
    die "the service is not running; see the log above"
fi
