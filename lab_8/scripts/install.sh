#!/usr/bin/env bash
# =============================================================================
# Лабораторная работа 8. Программа №1 (install.sh)
# Установка СУБД: всё выполняется внутри Docker.
#   1) docker compose up -d --build  (СУБД mysql:8.4 + контейнер-клиент python)
#   2) ожидание готовности СУБД по healthcheck
#   3) создание тестовой БД company и таблиц employees, audit_log
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[install] 1/3. Запуск стека lab_8 (docker compose up -d --build)..."
docker compose up -d --build

echo "[install] 2/3. Ожидание готовности MySQL (healthcheck, может занять ~30-60 c)..."
status="starting"
for i in $(seq 1 90); do
    status="$(docker inspect --format '{{.State.Health.Status}}' lab8-mysql 2>/dev/null || echo unknown)"
    if [ "$status" = "healthy" ]; then
        echo "[install] MySQL healthy (попытка ${i}, ~$((i * 2)) c)"
        break
    fi
    sleep 2
done
if [ "$status" != "healthy" ]; then
    echo "[install] ОШИБКА: MySQL не перешёл в состояние healthy" >&2
    docker compose logs --tail 50 mysql >&2 || true
    exit 1
fi

echo "[install] 3/3. Создание тестовой БД company и таблиц employees, audit_log"
docker compose exec -T mysql sh -c \
    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot --default-character-set=utf8mb4' \
    < sql/schema.sql

echo "[install] Проверка: версия сервера и содержимое таблицы employees"
docker compose exec -T mysql sh -c \
    'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot --default-character-set=utf8mb4 \
     -e "SELECT VERSION() AS mysql_version; SELECT id, name, salary, passport_no FROM company.employees;"'

echo "[install] Готово: СУБД установлена и запущена, БД company создана."
