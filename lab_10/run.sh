#!/usr/bin/env bash
# run.sh — одна команда для лабораторной работы №10:
# собрать образ, запустить контейнер и сохранить весь вывод.
# Требуется только docker (с плагином compose); на хосте больше ничего
# не устанавливается и не запускается.
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null 2>&1 || { echo "ОШИБКА: docker не найден" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ОШИБКА: docker compose недоступен" >&2; exit 1; }

# артефакты лабораторной (реально захваченный вывод)
mkdir -p demo_output
export HOST_UID="$(id -u)"
export HOST_GID="$(id -g)"

echo "[run.sh] Очистка предыдущих запусков..."
docker compose down --remove-orphans >/dev/null 2>&1 || true

echo "[run.sh] Сборка образа lab_10..."
docker compose build

echo "[run.sh] Запуск контейнера lab_10 (весь вывод сохраняется в demo_output/run_full.log)..."
set +e
docker compose up --abort-on-container-exit 2>&1 | tee demo_output/run_full.log
rc=${PIPESTATUS[0]}
set -e

echo "[run.sh] Остановка и удаление контейнера..."
docker compose down --remove-orphans >/dev/null 2>&1 || true

echo "[run.sh] Готово. Код возврата контейнера: $rc"
echo "[run.sh] Артефакты: $(ls demo_output | sort | tr '\n' ' ')"
exit "$rc"
