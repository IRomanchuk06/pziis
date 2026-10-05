#!/bin/bash
# Запуск nginx + sshd внутри "защищаемого сервера".
set -u

# Маршрут до outside-подсети через контейнер suricata (L3 gateway),
# чтобы ответы сервера тоже проходили через точку анализа.
ip route replace "${ATTACKER_NET}" via "${GATEWAY_IP}" \
    || echo "WARN: не удалось добавить маршрут через ${GATEWAY_IP}" >&2

nginx -g 'daemon off;' &
NGINX_PID=$!

mkdir -p /run/sshd
# -E: sshd пишет свой лог напрямую в файл (внутри контейнера нет syslog)
/usr/sbin/sshd -E /var/log/auth.log

echo "[start.sh] nginx pid=${NGINX_PID}, sshd запущен, route -> ${GATEWAY_IP}"
tail -F /var/log/nginx/access.log /var/log/auth.log
