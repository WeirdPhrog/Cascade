#!/bin/bash
# Run only on an expendable GitHub Actions VM (uses the actual systemd).
set -Eeuo pipefail
sudo bash install.sh --no-menu
sudo systemctl is-enabled --quiet cascade.service
sudo systemctl is-active --quiet cascade.service
sudo cascade list
sudo gokaskad --version
sudo bash install.sh --no-menu
sudo systemctl reload cascade.service
sudo systemctl restart cascade.service
sudo systemd-analyze verify /etc/systemd/system/cascade.service
sudo bash install.sh --uninstall
[[ ! -e /usr/local/bin/cascade ]]
[[ ! -e /usr/local/bin/gokaskad ]]
[[ ! -e /etc/systemd/system/cascade.service ]]
sudo bash install.sh --uninstall
echo 'PASS: install, reinstall, systemd reload/restart, uninstall twice'
