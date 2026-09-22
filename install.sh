#!/bin/bash
# Install only reviewed code from this repository. Never execute an upstream gist.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
REPO=https://raw.githubusercontent.com/WeirdPhrog/Cascade/main
EXPECTED_SHA256=4488b7cdc6d8a6e8d713cc274eceb3355c8ec774fd5be1c76e6fb4b4df13d4c3
PROGRAM=/usr/local/lib/cascade/cascade.py
UNIT=/etc/systemd/system/cascade.service
NO_MENU=0
ACTION=install
case "${1:-}" in
    --no-menu) NO_MENU=1 ;;
    --uninstall) ACTION=uninstall ;;
    --help) printf '%s\n' 'sudo bash install.sh [--no-menu|--uninstall]'; exit 0 ;;
    '') ;;
    *) printf '%s\n' 'Неизвестный параметр. Используйте --help.' >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || exit 2
[[ $EUID -eq 0 && $(uname -s) == Linux ]] || { echo 'Нужен Linux и sudo/root.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'Нужна система с работающим systemd.' >&2; exit 1; }
exec 9>/run/lock/cascade-install.lock
flock -x 9

if [[ $ACTION == uninstall ]]; then
    if [[ ! -f $PROGRAM ]]; then
        echo 'Cascade не установлен.'
        exit 0
    fi
    # Keep files if removing runtime rules or stopping the unit fails.
    /usr/bin/python3 "$PROGRAM" clear --yes
    systemctl disable --now cascade.service
    rm -f -- "$UNIT" /usr/local/bin/cascade
    if [[ $(readlink /usr/local/bin/gokaskad 2>/dev/null || true) == "$PROGRAM" ]]; then
        rm -f -- /usr/local/bin/gokaskad
    fi
    rm -f -- "$PROGRAM" /etc/cascade/state.json
    # Keep .lock and its directory: never unlink a lock held by another process.
    rmdir /usr/local/lib/cascade 2>/dev/null || true
    systemctl daemon-reload
    echo 'Cascade удалён. Системные пакеты и чужой firewall сохранены.'
    exit 0
fi

# shellcheck disable=SC1091
source /etc/os-release
case "$ID:${VERSION_ID:-}" in
    debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) ;;
    *) echo 'Поддерживаются Debian 12/13 и Ubuntu 22.04/24.04.' >&2; exit 1 ;;
esac

# Refuse to silently overwrite the original gist installation or another program.
for entry in /usr/local/bin/cascade /usr/local/bin/gokaskad; do
    if [[ -e $entry || -L $entry ]]; then
        [[ $(readlink "$entry" || true) == "$PROGRAM" ]] || {
            echo "Файл $entry принадлежит другой установке. См. docs/MIGRATION.md." >&2; exit 1;
        }
    fi
done
if [[ -e $UNIT ]] && ! grep -q '^# Cascade managed unit v1$' "$UNIT"; then
    echo "Файл $UNIT не принадлежит Cascade." >&2; exit 1
fi
for directory in /etc/cascade /usr/local/lib/cascade; do
    [[ ! -L $directory ]] || { echo "Символическая ссылка вместо $directory" >&2; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 nftables conntrack iproute2 ca-certificates curl

scratch=$(mktemp -d /tmp/cascade-install.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -f $source_dir/cascade.py ]]; then
    cp -- "$source_dir/cascade.py" "$scratch/cascade.py"
else
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
        --connect-timeout 15 --max-time 120 "$REPO/cascade.py" -o "$scratch/cascade.py"
fi
printf '%s  %s\n' "$EXPECTED_SHA256" "$scratch/cascade.py" | sha256sum --check --status || {
    echo 'Контрольная сумма cascade.py не совпала. Скачайте install.sh и cascade.py одной версии.' >&2; exit 1;
}
/usr/bin/python3 -I "$scratch/cascade.py" --version
cat > "$scratch/cascade.service" <<'UNIT'
# Cascade managed unit v1
[Unit]
Description=Cascade IPv4 TCP/UDP relay
Wants=network-online.target
After=network-online.target nftables.service netfilter-persistent.service ufw.service firewalld.service docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -I /usr/local/lib/cascade/cascade.py apply
ExecReload=/usr/bin/python3 -I /usr/local/lib/cascade/cascade.py apply
ExecStop=/usr/bin/python3 -I /usr/local/lib/cascade/cascade.py stop
TimeoutStartSec=90
TimeoutStopSec=90
UMask=0077
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=/etc/cascade
# Legacy iptables inspection uses a raw socket even though it is read-only.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
UNIT

had_program=0
had_unit=0
was_enabled=0
was_active=0
[[ ! -f $PROGRAM ]] || { cp -- "$PROGRAM" "$scratch/old.py"; had_program=1; }
[[ ! -f $UNIT ]] || { cp -- "$UNIT" "$scratch/old.service"; had_unit=1; }
systemctl is-enabled --quiet cascade.service 2>/dev/null && was_enabled=1
systemctl is-active --quiet cascade.service 2>/dev/null && was_active=1
rollback() {
    local result=$?
    trap - ERR
    set +e
    journalctl -u cascade.service -n 30 --no-pager >&2
    if [[ $had_program == 1 ]]; then
        install -m 0755 "$scratch/old.py" "$PROGRAM"
    else
        rm -f -- "$PROGRAM" /usr/local/bin/cascade /usr/local/bin/gokaskad
    fi
    if [[ $had_unit == 1 ]]; then
        install -m 0644 "$scratch/old.service" "$UNIT"
    else
        rm -f -- "$UNIT"
    fi
    [[ $was_enabled == 1 ]] || systemctl disable cascade.service
    systemctl daemon-reload
    if [[ $was_active == 1 && $had_program == 1 ]]; then
        systemctl reload cascade.service
    fi
    echo 'Установка не завершена; предыдущие файлы восстановлены. Проверьте ошибки выше.' >&2
    exit "$result"
}
trap rollback ERR
install -d -m 0700 /etc/cascade
install -d -m 0755 /usr/local/lib/cascade
install -m 0755 "$scratch/cascade.py" /usr/local/lib/cascade/.cascade.py.new
mv -f -- /usr/local/lib/cascade/.cascade.py.new "$PROGRAM"
ln -sfn -- "$PROGRAM" /usr/local/bin/cascade
ln -sfn -- "$PROGRAM" /usr/local/bin/gokaskad
install -m 0644 "$scratch/cascade.service" "$UNIT"
systemctl daemon-reload
systemctl enable cascade.service
if [[ $was_active == 1 ]]; then
    systemctl reload cascade.service
else
    systemctl start cascade.service
fi
trap - ERR
echo 'Cascade установлен. Команды: cascade / gokaskad; справка: cascade --help'
if [[ $NO_MENU == 0 && -t 0 ]]; then
    flock -u 9
    exec /usr/bin/python3 -I "$PROGRAM" menu
fi
