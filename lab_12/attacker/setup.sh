#!/bin/bash
# Настройка маршрутизации на узле атакующего:
# весь трафик к защищаемой сети идёт через контейнер suricata (L3 gateway).
set -u

ip route replace "${SECURE_NET}" via "${GATEWAY_IP}" \
    || echo "WARN: не удалось добавить маршрут через ${GATEWAY_IP}" >&2

echo "[attacker] маршрут до ${SECURE_NET} через ${GATEWAY_IP}:"
ip route show

exec sleep infinity
