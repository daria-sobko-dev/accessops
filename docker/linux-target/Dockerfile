# Test Linux server managed by Ansible.
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server python3 sudo procps \
 && rm -rf /var/lib/apt/lists/*

# Service account for Ansible: SSH key only (no password), passwordless sudo.
RUN useradd --create-home --shell /bin/bash --comment "Ansible service account" ansible \
 && printf 'ansible ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/ansible \
 && chmod 0440 /etc/sudoers.d/ansible \
 && visudo -cf /etc/sudoers.d/ansible \
 && install -d -m 0700 -o ansible -g ansible /home/ansible/.ssh \
 && rm -f /etc/ssh/ssh_host_*

COPY sshd-hardening.conf /etc/ssh/sshd_config.d/00-accessops.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
