#!/bin/sh
# Prepare SSH files for Ansible in /run/accessops (tmpfs: memory only, gone on restart),
# then start the API. Never prints secret contents.
set -eu
umask 077

STATE=/run/accessops
KEY_SECRET=/run/secrets/ansible_ssh_key
HOST_KEY=/etc/accessops/linux-target-host-key.pub

if [ ! -s "$KEY_SECRET" ]; then
    echo "ERROR: compose secret ansible_ssh_key is empty." \
         "Run: python -m accessops api-bootstrap, then recreate accessops-api." >&2
    exit 1
fi
base64 -d "$KEY_SECRET" > "$STATE/ansible_ed25519"
chmod 600 "$STATE/ansible_ed25519"

# Pin linux-target's host key: SSH refuses to talk to any other server under that name.
if [ ! -s "$HOST_KEY" ]; then
    echo "ERROR: $HOST_KEY is missing: is linux-target running?" >&2
    exit 1
fi
printf 'linux-target %s\n' "$(cut -d ' ' -f 1,2 "$HOST_KEY")" > "$STATE/known_hosts"

mkdir -p "$STATE/credentials"
exec "$@"
