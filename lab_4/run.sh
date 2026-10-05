#!/usr/bin/env bash
# Лабораторная работа № 4. Единственная команда запуска на хосте.
# Собирает образы, запускает демонстрацию в контейнере и сохраняет вывод
# в demo_output/. Попытка запуска CryptGenRandom под wine — best-effort.
set -u
cd "$(dirname "$0")"

mkdir -p demo_output
LOG=demo_output/run.log

{
  echo "### lab_4 run started: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo
  echo "== [1/3] Сборка основного образа (g++, python3, MinGW) =="
  docker compose -p lab_4 build lab4 || { echo "FATAL: build lab4 failed"; exit 1; }

  echo
  echo "== [2/3] Демонстрация в контейнере =="
  docker compose -p lab_4 run --rm lab4 || echo "WARNING: demo exit code != 0"

  echo
  echo "== [3/3] Попытка запуска CryptGenRandom под wine (best-effort) =="
  if docker compose -p lab_4 build winetest 2>demo_output/wine_build_errors.log; then
    docker compose -p lab_4 run --rm winetest \
      || echo "WARNING: wine-запуск не удался — анализ gen_crypt.exe требует Windows (ВМ)"
  else
    echo "NOTE: сборка winetest-образа не удалась (слишком тяжёлый/нет сети)."
    echo "      Анализ CryptGenRandom требует запуска gen_crypt.exe в Windows (ВМ)."
  fi

  echo
  echo "== Итоговые файлы demo_output/ =="
  ls -lR demo_output/ || true
  echo
  echo "### lab_4 run finished: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
} 2>&1 | tee "$LOG"
