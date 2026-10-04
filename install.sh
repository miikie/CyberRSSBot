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
as_app() { (cd "$APP" && runuser -u "$APP_USER" -- "$@"); }

[ "$(id -u)" -eq 0 ] || die "run as root: bash install.sh"
command -v apt-get >/dev/null || die "this script expects Debian or Ubuntu"

if [ -z "${CYBERRSSBOT_UPDATED:-}" ] && [ -d "$SRC/.git" ] && command -v git >/dev/null; then
    step "Fetching the latest code"
    before="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || true)"
    if git -C "$SRC" -c safe.directory="$SRC" pull --ff-only; then
        after="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || true)"
        if [ "$before" != "$after" ]; then
            echo "Updated $(echo "$before" | cut -c1-7) -> $(echo "$after" | cut -c1-7); restarting the installer."
            CYBERRSSBOT_UPDATED=1 exec bash "$SRC/install.sh" "$@"
        fi
        echo "Already up to date."
    else
        echo "Could not update from git (no network, or local changes); continuing with the code already here."
    fi
fi

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

if [ -f "$APP/config.yaml" ]; then
    OLD_DB="$(sed -n 's/^database:[[:space:]]*//p' "$APP/config.yaml" | tr -d '"'"'"' ')"
    OLD_DB="${OLD_DB:-cyberrssbot.db}"
    if [ -f "$APP/$OLD_DB" ]; then
        step "Saving a copy of the database before the update"
        mkdir -p "$BASE/backups"
        snapshot="$BASE/backups/pre-update-$(date +%F-%H%M%S).db"
        if sqlite3 "$APP/$OLD_DB" ".backup '$snapshot'"; then
            echo "saved $snapshot"
            ls -1t "$BASE"/backups/pre-update-*.db 2>/dev/null | tail -n +4 | xargs -r rm -f
        else
            echo "Could not snapshot the database; continuing."
        fi
    fi
fi

step "Copying code to $APP"
if [ "$SRC" != "$APP" ]; then
    rm -rf "$APP/cyberrssbot" "$APP/kb"
    cp -a "$SRC/cyberrssbot" "$SRC/requirements.txt" "$APP/"
    [ -d "$SRC/kb" ] && cp -a "$SRC/kb" "$APP/"
    for f in README.md LICENSE config.example.yaml .env.example; do
        [ -f "$SRC/$f" ] && cp -a "$SRC/$f" "$APP/"
    done
fi
[ -d "$APP/kb" ] || die "the kb/ folder is missing from $SRC; the checkout is incomplete"

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

step "Adding new settings and sources to config.yaml"
echo "Your existing values are kept. You will be asked for any channel ID that is not set yet."
echo "Press Enter to skip them all: channels are easier to set from Discord with /channel set."
as_app "$VENV/bin/python" -m cyberrssbot --upgrade-config \
    || echo "config.yaml could not be upgraded automatically; it was left as it was."

step "Checking every source once (posts nothing; the first run downloads about 55 MB of reference data)"
as_app "$VENV/bin/python" -m cyberrssbot --check || echo "Some sources failed the check; the service is installed anyway."

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
sleep 12
journalctl -u cyberrssbot -n 25 --no-pager || true
echo
if systemctl is-active --quiet cyberrssbot; then
    echo "The bot is running and will start automatically on boot."
    echo "Lines above that start with \"channel '...'\" are channels the bot cannot post to. In Discord, fix the"
    echo "permissions and run /channel check, or point the category elsewhere with /channel set."
    echo "Logs: journalctl -u cyberrssbot -f     Update: bash install.sh     Settings: nano $APP/config.yaml"
else
    die "the service is not running; see the log above"
fi
