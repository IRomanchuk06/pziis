#!/usr/bin/env bash
# =============================================================================
# Лабораторная работа 8. Программа №4 (uninstall.sh)
# Удаление СУБД и созданных ею объектов:
#   - контейнеры lab8-mysql (СУБД) и lab8-client (клиент);
#   - внутренняя сеть compose lab_8_lab8net;
#   - том mysql_data с данными СУБД (БД company, учётные записи, привилегии);
#   - локально собранный образ клиента lab8-client.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[uninstall] Остановка и удаление стека lab_8 (down -v: контейнеры + сеть + тома)"
docker compose down -v --rmi local --remove-orphans

echo "[uninstall] Проверка оставшихся артефактов проекта lab_8:"
leftover_volumes="$(docker volume ls --format '{{.Name}}' | grep '^lab_8_' || true)"
leftover_networks="$(docker network ls --format '{{.Name}}' | grep '^lab_8_' || true)"
leftover_containers="$(docker ps -a --format '{{.Names}}' | grep -E '^lab8-' || true)"

if [ -z "$leftover_volumes" ] && [ -z "$leftover_networks" ] && [ -z "$leftover_containers" ]; then
    echo "  контейнеры, сеть, тома: отсутствуют (удалены полностью)"
else
    [ -n "$leftover_containers" ] && echo "  контейнеры: $leftover_containers"
    [ -n "$leftover_networks" ]   && echo "  сети:       $leftover_networks"
    [ -n "$leftover_volumes" ]    && echo "  тома:       $leftover_volumes"
fi

echo "[uninstall] Готово: СУБД и созданные ею объекты удалены."
