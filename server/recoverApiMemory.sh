#!/usr/bin/env bash
# Reversible, host-specific mitigation for the observed V8 heap exhaustion.
set -euo pipefail
unit=bdppt-site.service
dir="/etc/systemd/system/$unit.d"
dropin="$dir/90-api-heap-20261127.conf"
pid=$(systemctl show "$unit" -p MainPID --value)
[[ "$pid" =~ ^[1-9][0-9]*$ ]]
# Refuse to replace any pre-existing runtime options or operator override.
if sudo test -e "$dropin"; then echo 'Drop-in already exists'; exit 1; fi
if sudo grep -zq '^NODE_OPTIONS=.' "/proc/$pid/environ"; then echo 'Existing runtime options require a merge'; exit 1; fi
if sudo grep -zEq '^--max[-_]old[-_]space[-_]size' "/proc/$pid/cmdline"; then echo 'Existing command-line heap option'; exit 1; fi
sudo mkdir -p "$dir"
printf '%s\n' '[Service]' 'Environment="NODE_OPTIONS=--max-old-space-size=768"' | sudo tee "$dropin" >/dev/null
rollback() {
    sudo rm -f -- "$dropin"
    sudo systemctl daemon-reload
    sudo systemctl restart "$unit"
}
trap rollback ERR
sudo systemctl daemon-reload
sudo systemctl restart "$unit"
for attempt in $(seq 1 80); do
    if curl -fsS --max-time 4 http://127.0.0.1:3001/api/vendors/status >/dev/null; then
        pid=$(systemctl show "$unit" -p MainPID --value)
        sudo grep -zqx 'NODE_OPTIONS=--max-old-space-size=768' "/proc/$pid/environ"
        printf 'API ready with 768 MiB V8 old space, pid=%s\n' "$pid"
        exit 0
    fi
    sleep 2
done
false
