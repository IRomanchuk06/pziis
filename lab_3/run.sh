#!/usr/bin/env bash
# ЛР3: одна команда -- собрать образ, выполнить демонстрацию в контейнере,
# сохранить весь вывод в demo_output/.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p demo_output
HOST_UID="$(id -u)" HOST_GID="$(id -g)" docker compose -p lab_3 up --build --abort-on-container-exit
echo
echo "Готово. Артефакты: $(pwd)/demo_output (отчёт: report/report.md)"
