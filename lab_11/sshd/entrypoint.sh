#!/bin/sh
# Точка входа sshd-контейнера.
# Генерация host-ключей при первом старте; журналирование в /var/log/auth.log.
# OpenSSH 9.6 при -E пишет строки БЕЗ отметок времени, поэтому вывод sshd
# направляется через ts (moreutils), который добавляет syslog-подобный
# префикс с меткой UTC: "2026-10-05T12:00:00+00:00 lab11-sshd sshd: ...".
set -e

mkdir -p /run/sshd /var/log

if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    echo "[entrypoint] generating SSH host keys..."
    ssh-keygen -A
fi

rm -f /var/log/auth.log

/usr/sbin/sshd -D -e 2>&1 \
    | stdbuf -oL ts '%Y-%m-%dT%H:%M:%S+00:00 lab11-sshd sshd: ' \
    >> /var/log/auth.log
