#!/usr/bin/env bash
# Лабораторная работа 5: одна команда = сборка + запуск в контейнере +
# сохранение вывода в demo_output/lab5_output.txt.
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

echo "[lab_5] шаг 1/3: сборка образа lab5:latest (FROM python:3.12-slim)..."
"${DC[@]}" -p lab_5 build

echo
echo "[lab_5] шаг 2/3: запуск демонстрации в контейнере..."
echo "=============================================================="
"${DC[@]}" -p lab_5 run --rm lab5

echo
echo "[lab_5] шаг 3/3: добавление метаданных прогона..."
{
  echo
  echo "--------------------------------------------------------------"
  echo "Метаданные прогона:"
  echo "  дата/время : $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "  образ      : lab5:latest (FROM python:3.12-slim)"
  echo "  docker     : $(docker --version)"
  echo "  проект     : lab_5 (docker compose)"
} >> "$OUT/lab5_output.txt"

echo
echo "[lab_5] Готово. Вывод сохранён в: $OUT/lab5_output.txt"
