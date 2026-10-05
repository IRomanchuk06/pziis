#!/usr/bin/env bash
# Одна команда: собрать образ, запустить демонстрацию в контейнере,
# сохранить вывод в demo_output/.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p demo_output
OUT="demo_output/demo_run_$(date +%Y%m%d_%H%M%S).log"

docker compose build
docker compose run --rm -T app | tee "$OUT"
cp "$OUT" demo_output/demo_run.log

echo
echo "Лог сохранён: $OUT (копия: demo_output/demo_run.log)"
