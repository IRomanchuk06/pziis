#!/usr/bin/env bash
# ============================================================================
# Лабораторная работа №11 «Анализ запросов из сети Интернет».
# Одна команда выполняет весь цикл:
#   1) сборка образов и запуск web (nginx) и sshd (OpenSSH);
#   2) синтетический backfill журналов за 5 предыдущих дней;
#   3) живой прогон: реальные curl- и SSH-запросы (сегодняшний день);
#   4) анализ журналов -> demo_output/analysis_report.txt;
#   5) сохранение журналов и вывода в demo_output/ (+ права пользователя хоста);
#   6) остановка стенда.
# Всё выполняется только внутри docker-контейнеров.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

LOG_DIR=runtime/logs
OUT_DIR=demo_output

echo "[run.sh] Проект: lab_11 (docker compose)"
mkdir -p "$LOG_DIR" "$OUT_DIR"

# Чистый прогон: гасим прошлый стенд и удаляем старые журналы/выводы.
docker compose down --remove-orphans >/dev/null 2>&1 || true
rm -f "$LOG_DIR/access.log" "$LOG_DIR/error.log" "$LOG_DIR/auth.log"
rm -f "$OUT_DIR/access.log" "$OUT_DIR/error.log" "$OUT_DIR/auth.log" \
      "$OUT_DIR/analysis_report.txt" "$OUT_DIR/live_run.txt"

echo "[run.sh] Шаг 1/6: сборка образов (web готовый образ, sshd и client собираются)..."
docker compose build

echo "[run.sh] Шаг 2/6: запуск web и sshd (порты наружу не публикуются)..."
docker compose up -d web sshd

echo "[run.sh] Шаг 3/6: синтетический backfill журналов за 5 предыдущих дней..."
docker compose run --rm --no-deps -T client \
    python /workspace/generator/backfill.py

echo "[run.sh] Шаг 4/6: живой прогон — реальные curl- и SSH-запросы..."
docker compose run --rm --no-deps -T client \
    python /workspace/generator/live.py

echo "[run.sh] Шаг 5/6: анализ журналов..."
docker compose run --rm --no-deps -T client \
    python /workspace/analysis/analyze.py \
        --access /workspace/runtime/logs/access.log \
        --error  /workspace/runtime/logs/error.log \
        --auth   /workspace/runtime/logs/auth.log \
        --out    /workspace/demo_output/analysis_report.txt

echo "[run.sh] Шаг 6/6: остановка стенда и сохранение результатов..."
docker compose down
docker compose run --rm --no-deps -T client sh -c \
    "cp runtime/logs/access.log runtime/logs/error.log runtime/logs/auth.log demo_output/ \
     && chown -R $(id -u):$(id -g) runtime demo_output"

echo "[run.sh] Готово. Результаты:"
echo "  demo_output/access.log, error.log, auth.log   — журналы за 6 дней"
echo "  demo_output/live_run.txt                      — транскрипт живого прогона"
echo "  demo_output/analysis_report.txt               — отчёт анализатора"
echo "  report/report.md                              — отчёт по лабораторной"
