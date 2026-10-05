#!/usr/bin/env bash
# Лабораторная работа 6: одна команда = сборка + запуск в контейнере +
# сохранение вывода в demo_output/.
#
# Запуск:  ./run.sh
# Требуется: docker + docker compose v2. На хосте ничего не устанавливается.
set -euo pipefail
cd "$(dirname "$0")"

# docker compose v2 или legacy docker-compose
DC=(docker compose)
if ! docker compose version >/dev/null 2>&1; then
  DC=(docker-compose)
fi

export LAB_UID="$(id -u)" LAB_GID="$(id -g)"
OUT=demo_output
mkdir -p "$OUT"

echo "[lab_6] шаг 1/3: сборка образа lab6:latest (FROM ubuntu:24.04 + openssl)..."
"${DC[@]}" -p lab_6 build

echo
echo "[lab_6] шаг 2/3: запуск демонстрации в контейнере (займёт ~20 секунд)..."
echo "=============================================================="
"${DC[@]}" -p lab_6 run --rm lab6

echo
echo "[lab_6] шаг 3/3: добавление метаданных прогона..."
{
  echo
  echo "--------------------------------------------------------------"
  echo "Метаданные прогона:"
  echo "  дата/время : $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "  образ      : lab6:latest (FROM ubuntu:24.04, openssl из apt)"
  echo "  docker     : $(docker --version)"
  echo "  проект     : lab_6 (docker compose)"
} >> "$OUT/lab6_full_log.txt"

echo
echo "[lab_6] Готово. Вывод сохранён в: $OUT/ (per-step файлы + lab6_full_log.txt)"
