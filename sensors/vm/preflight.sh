#!/usr/bin/env bash
# Phase 14C - READ-ONLY sensor preflight (Kali). Changes NOTHING: no writes, no chmod/chown, no service control,
# no package operations. It only prints facts about Suricata, its EVE file/config and (if present) the adapter service.
# It prints counts and configuration lines only - never EVE record contents and never any secret.
#
# Usage:   bash preflight.sh            (uses sudo only to READ root-owned files; you will be asked for your password)
#          bash preflight.sh 2>&1 | tee ~/preflight-output.txt      (writes a file only because YOU redirect it)
set -u

EVE="${SURICATA_EVE_PATH:-/var/log/suricata/eve.json}"
YAML="${SURICATA_YAML:-/etc/suricata/suricata.yaml}"

section() { printf '\n===== %s =====\n' "$1"; }

section "versions"
suricata -V 2>&1 | head -2
python3 --version 2>&1
systemctl --version 2>/dev/null | head -1
command -v jq >/dev/null 2>&1 && jq --version || echo "jq: not installed (event-type counts below will be skipped)"

section "how Suricata is run"
systemctl is-active suricata 2>&1
systemctl is-enabled suricata 2>&1
ps -o user,pid,args -C suricata 2>&1 | cut -c1-200

section "log directory and EVE file ownership/mode"
sudo ls -ld /var/log/suricata 2>&1
sudo ls -l "$EVE" "$EVE".* 2>&1 | head -12
echo "--- logrotate config"
sudo cat /etc/logrotate.d/suricata 2>&1 | head -30
echo "--- groups"
getent group soc-eve 2>&1 || echo "group soc-eve: not present"
getent passwd soc-adapter 2>&1 || echo "user soc-adapter: not present"
id

section "effective eve-log block (active, non-comment lines only)"
sudo awk '/- eve-log:/,/- syslog:/' "$YAML" 2>&1 | grep -vE '^[[:space:]]*(#|$)' | head -80

section "effective af-packet block (active, non-comment lines only)"
sudo awk '/^af-packet:/,/^pcap:/' "$YAML" 2>&1 | grep -vE '^[[:space:]]*(#|$)' | head -40

section "checksum-related settings (all lines, including commented defaults)"
sudo grep -nE 'checksum-(checks|validation)' "$YAML" 2>&1 | head -20
echo "--- run-as / user / group"
sudo grep -nE '^[[:space:]]*(run-as:|user:|group:)' "$YAML" 2>&1 | head -6

section "EVE event-type counts (counts only)"
if command -v jq >/dev/null 2>&1; then
  sudo jq -r '.event_type' "$EVE" 2>/dev/null | sort | uniq -c | sort -rn | head -20
else
  echo "skipped (no jq)"
fi

section "sensitive raw fields present in EVE (line COUNTS only, contents are not printed)"
if command -v jq >/dev/null 2>&1; then
  for k in payload payload_printable packet http_body http; do
    printf '%s: ' "$k"; sudo jq -c "select(.$k != null)" "$EVE" 2>/dev/null | wc -l
  done
  printf 'tls.certificate/chain: '; sudo jq -c 'select(.tls.certificate != null or .tls.chain != null)' "$EVE" 2>/dev/null | wc -l
  printf 'dns requests: '; sudo jq -c 'select(.event_type=="dns" and .dns.type=="request")' "$EVE" 2>/dev/null | wc -l
  printf 'community_id present: '; sudo jq -c 'select(.community_id != null)' "$EVE" 2>/dev/null | wc -l
else
  echo "skipped (no jq)"
fi

section "capture interface facts"
ethtool -i eth1 2>&1 | head -5
ip -d link show eth1 2>&1 | head -4
ethtool -k eth1 2>/dev/null | grep -iE 'checksum|segmentation|receive-offload' | head -12

section "adapter service (if already installed - read-only status)"
systemctl is-active soc-suricata-adapter 2>&1
systemctl is-enabled soc-suricata-adapter 2>&1
sudo ls -ld /etc/soc-suricata-adapter /var/lib/soc-suricata-adapter /opt/soc-suricata-adapter 2>&1 | head -6
sudo ls -l /etc/soc-suricata-adapter 2>&1 | head -6

section "done - nothing was changed"
