#!/usr/bin/env bash
# ЛР7: одна команда -- собрать образ, выполнить оценку по методике в контейнере,
# сохранить все артефакты в demo_output/.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p demo_output
HOST_UID="$(id -u)" HOST_GID="$(id -g)" docker compose -p lab_7 up --build --abort-on-container-exit
echo
echo "Готово. Артефакты: $(pwd)/demo_output (отчёт: report/report.md)"
