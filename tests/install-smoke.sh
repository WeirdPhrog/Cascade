#!/bin/bash
# Run only on an expendable GitHub Actions VM (uses the actual systemd).
set -Eeuo pipefail
# Never use this fixture on an existing installation.
for file in /usr/local/lib/cascade/cascade.py /usr/local/bin/cascade /etc/systemd/system/cascade.service; do
    [[ ! -e $file && ! -L $file ]] || { echo "Test requires a fresh VM: $file" >&2; exit 1; }
done
sudo bash install.sh --no-menu
sudo systemctl is-enabled --quiet cascade.service
sudo systemctl is-active --quiet cascade.service
sudo cascade list
sudo cascade --version

# Exercise the real unit with saved rules, while all network changes stay in a netns.
namespace="cascade-smoke-$$"
scratch=$(mktemp -d)
cleanup() {
    sudo journalctl -u cascade.service -n 40 --no-pager
    sudo systemctl stop cascade.service 2>/dev/null || true
    sudo rm -f /etc/systemd/system/cascade.service.d/network-test.conf
    sudo rm -f /etc/systemd/system/cascade.service.d/failure-test.conf
    sudo rmdir /etc/systemd/system/cascade.service.d 2>/dev/null || true
    sudo systemctl daemon-reload
    sudo ip netns delete "$namespace" 2>/dev/null || true
    rm -rf -- "$scratch"
}
trap cleanup EXIT
sudo ip netns add "$namespace"
sudo ip -n "$namespace" link set lo up
sudo ip -n "$namespace" addr add 198.18.0.1/24 dev lo
sudo ip netns exec "$namespace" sysctl -w net.ipv4.ip_forward=0
sudo systemctl stop cascade.service
sudo mkdir -p /etc/systemd/system/cascade.service.d
printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' "$namespace" | sudo tee /etc/systemd/system/cascade.service.d/network-test.conf
sudo systemctl daemon-reload
sudo systemctl start cascade.service
sudo ip netns exec "$namespace" cascade add --proto udp --listen 198.18.0.1 --in-port 45000 --target 198.18.0.2 --out-port 45001
sudo bash install.sh --no-menu
sudo systemctl reload cascade.service
sudo systemctl restart cascade.service
sudo ip netns exec "$namespace" iptables -t nat -S CSCD_DNAT
[[ $(sudo ip netns exec "$namespace" sysctl -n net.ipv4.ip_forward) == 1 ]]
sudo systemctl stop cascade.service
if sudo ip netns exec "$namespace" iptables -t nat -S CSCD_DNAT; then
    echo 'Chain survived service stop' >&2
    exit 1
fi
[[ $(sudo ip netns exec "$namespace" sysctl -n net.ipv4.ip_forward) == 1 ]]
sudo systemctl start cascade.service
sudo ip netns exec "$namespace" iptables -t nat -S CSCD_DNAT
sudo systemd-analyze verify /etc/systemd/system/cascade.service
# Reinstall must restore the previous executable when systemd reload fails.
python3 - "$scratch" <<'PY'
import hashlib, re, sys
from pathlib import Path
destination = Path(sys.argv[1])
program = Path('/usr/local/lib/cascade/cascade.py').read_bytes()
(destination / 'before.py').write_bytes(program)
candidate = program + b'\n# Temporary install test candidate.\n'
(destination / 'cascade.py').write_bytes(candidate)
script = Path('install.sh').read_text()
(destination / 'install.sh').write_text(re.sub(r'EXPECTED_SHA256=[0-9a-f]+', 'EXPECTED_SHA256=' + hashlib.sha256(candidate).hexdigest(), script))
PY
sudo cp /etc/cascade/state.json "$scratch/before.json"
printf '[Service]\nExecReload=\nExecReload=/bin/false\n' | sudo tee /etc/systemd/system/cascade.service.d/failure-test.conf
sudo systemctl daemon-reload
if sudo bash "$scratch/install.sh" --no-menu; then
    echo 'Failed reload was reported as a successful install' >&2; exit 1
fi
cmp "$scratch/before.py" /usr/local/lib/cascade/cascade.py
sudo cmp "$scratch/before.json" /etc/cascade/state.json
sudo ip netns exec "$namespace" iptables -t nat -S CSCD_DNAT
sudo rm /etc/systemd/system/cascade.service.d/failure-test.conf
sudo systemctl daemon-reload
sudo systemctl reload cascade.service
# Removal must not delete a command now belonging to someone else.
sudo rm /usr/local/bin/cascade
printf 'foreign command\n' | sudo tee /usr/local/bin/cascade
if sudo bash install.sh --uninstall; then
    echo 'Uninstall accepted a foreign command' >&2; exit 1
fi
[[ $(cat /usr/local/bin/cascade) == 'foreign command' ]]
sudo ip netns exec "$namespace" iptables -t nat -S CSCD_DNAT
sudo rm /usr/local/bin/cascade
sudo ln -s /usr/local/lib/cascade/cascade.py /usr/local/bin/cascade
sudo ip netns exec "$namespace" bash install.sh --uninstall
[[ ! -e /usr/local/bin/cascade ]]
[[ ! -e /etc/systemd/system/cascade.service ]]
sudo bash install.sh --uninstall
# A subsequent clean installation must clear the deactivation barrier.
sudo bash install.sh --no-menu
sudo ip netns exec "$namespace" cascade add --proto udp --listen 198.18.0.1 --in-port 45000 --target 198.18.0.2
sudo ip netns exec "$namespace" bash install.sh --uninstall
echo 'PASS: install, failed reinstall rollback, systemd lifecycle, foreign-file protection, removal and clean reinstall'
