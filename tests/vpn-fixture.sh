#!/bin/bash
set -Eeuo pipefail
# The same rule shapes used by AmneziaWG's container start script.
ip link add wg0 type dummy 2>/dev/null || true
iptables -A INPUT -i wg0 -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A OUTPUT -o wg0 -j ACCEPT
iptables -A FORWARD -i wg0 -o eth0 -s 10.8.1.0/24 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE
exec python3 -u /echo.py
