#!/bin/bash
# Пуш всех лаб ПЗИИС в https://github.com/IRomanchuk06/pziis.git
set -e
cd "$(dirname "$0")"

REPO_URL="https://github.com/IRomanchuk06/pziis.git"

if [ ! -d .git ]; then
  git init -b main
fi

# идентификация: берём глобальную, иначе задаём репо-локальную нейтральную
if [ -z "$(git config user.email)" ]; then
  git config user.email "ivan@local"
  git config user.name "ivan"
  echo "[!] git identity не задана глобально — использована репо-локальная (ivan@local)"
fi

git add -A
echo "--- Будет закоммичено:"
git diff --cached --stat | tail -3
git commit -m "Лабораторные работы ПЗИИС: 1-8, 10-12 (код, docker, demo_output, отчёты)" || echo "[i] нечего коммитить"

if ! git remote | grep -q origin; then
  git remote add origin "$REPO_URL"
fi

echo "--- Пуш в $REPO_URL (ветка main)"
git push -u origin main
echo "OK: пуш завершён"
