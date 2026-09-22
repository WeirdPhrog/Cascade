#!/bin/bash
# Run only on an expendable GitHub Actions VM (uses the actual systemd).
set -Eeuo pipefail
sudo bash install.sh --no-menu
sudo systemctl is-enabled --quiet cascade.service
sudo systemctl is-active --quiet cascade.service
sudo cascade list
sudo gokaskad --version

# Exercise the real unit with saved rules, while all network changes stay in a netns.
namespace="cascade-smoke-$$"
cleanup() {
    sudo journalctl -u cascade.service -n 40 --no-pager
    sudo systemctl stop cascade.service 2>/dev/null || true
    sudo rm -f /etc/systemd/system/cascade.service.d/network-test.conf
    sudo rmdir /etc/systemd/system/cascade.service.d 2>/dev/null || true
    sudo systemctl daemon-reload
    sudo ip netns delete "$namespace" 2>/dev/null || true
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
sudo ip netns exec "$namespace" nft list table ip cascade_v1
[[ $(sudo ip netns exec "$namespace" sysctl -n net.ipv4.ip_forward) == 1 ]]
sudo systemctl stop cascade.service
if sudo ip netns exec "$namespace" nft list table ip cascade_v1; then
    echo 'Table survived service stop' >&2
    exit 1
fi
[[ $(sudo ip netns exec "$namespace" sysctl -n net.ipv4.ip_forward) == 0 ]]
sudo systemctl start cascade.service
sudo ip netns exec "$namespace" nft list table ip cascade_v1
sudo systemd-analyze verify /etc/systemd/system/cascade.service
sudo ip netns exec "$namespace" bash install.sh --uninstall
[[ ! -e /usr/local/bin/cascade ]]
[[ ! -e /usr/local/bin/gokaskad ]]
[[ ! -e /etc/systemd/system/cascade.service ]]
sudo bash install.sh --uninstall
echo 'PASS: install, reinstall, saved rules through real systemd reload/restart/stop/start, uninstall twice'
