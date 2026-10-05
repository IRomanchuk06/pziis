#!/usr/bin/env bash
# Одна команда: собрать образ аудитора, выполнить аудит lab_1 в контейнере,
# сохранить вывод в demo_output/.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p demo_output
OUT="demo_output/audit_run_$(date +%Y%m%d_%H%M%S).log"

docker compose build
# Код exit=1 означает наличие непройденных проверок — это честный результат аудита
docker compose run --rm -T auditor | tee "$OUT" || AUDIT_RC=$?
cp "$OUT" demo_output/audit_run.log

echo
echo "Лог сохранён: $OUT (копия: demo_output/audit_run.log)"
exit "${AUDIT_RC:-0}"
