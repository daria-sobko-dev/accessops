#!/bin/sh
set -eu

install -d -m 0755 /run/sshd /etc/ssh/hostkeys
if [ ! -f /etc/ssh/hostkeys/ssh_host_ed25519_key ]; then
    ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/hostkeys/ssh_host_ed25519_key
fi

# Public key of the Ansible service account, mounted read-only from the host.
if [ -f /etc/accessops/ansible_authorized_keys ]; then
    install -m 0600 -o ansible -g ansible \
        /etc/accessops/ansible_authorized_keys /home/ansible/.ssh/authorized_keys
else
    echo "WARNING: /etc/accessops/ansible_authorized_keys not found." \
         "Run: python -m accessops ssh-bootstrap, then restart linux-target." >&2
fi

/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
