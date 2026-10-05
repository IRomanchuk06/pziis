#!/usr/bin/env bash
# Лабораторная работа № 4. Попытка запуска gen_crypt.exe (CryptGenRandom) под wine.
# Best-effort: если wine не сможет выполнить программу, в лог честно пишется
# отказ; выход программы НЕ выдумывается. В этом случае анализ выполняется
# в Windows (ВМ) и файл demo_output/data/crypt_out.bin кладётся вручную,
# после чего достаточно повторно выполнить scripts/run_analysis.sh.
set -uo pipefail
cd /work

OUT=demo_output
mkdir -p "$OUT/data"

{
  echo "=== Запуск gen_crypt.exe (CryptGenRandom) под wine в docker ==="
  echo "wine: $(wine --version 2>&1 || echo 'wine недоступен')"
  export WINEDEBUG=-all
  export WINEPREFIX=/tmp/.wine
  export WINEARCH=win64
  export HOME=/tmp

  echo "-- инициализация префикса wine (wineboot)..."
  timeout 180 wineboot -u >/dev/null 2>&1
  echo "wineboot exit: $?"

  echo "-- запуск: wine bin/gen_crypt.exe crypt_out.bin 1048576 (cwd=$OUT/data)"
  ( cd "$OUT/data" && timeout 240 wine /work/bin/gen_crypt.exe crypt_out.bin 1048576 )
  rc=$?
  echo "gen_crypt.exe exit code: $rc"
  if [ -f "$OUT/data/crypt_out.bin" ]; then
    echo "-- результат:"
    ls -l "$OUT/data/crypt_out.bin"
  else
    echo "-- файл crypt_out.bin НЕ создан: запуск под wine не удался."
    echo "   Анализ CryptGenRandom требует запуска в Windows (ВМ)."
    echo "   Компиляция gen_crypt.exe успешно выполнена (см. build.log)."
  fi
} 2>&1 | tee "$OUT/cryptgen_wine.txt"

if [ -f "$OUT/data/crypt_out.bin" ]; then
  echo "== crypt_out.bin получен: обновляю таблицы и анализы ==" | tee -a "$OUT/cryptgen_wine.txt"
  bash scripts/run_analysis.sh
  echo "CRYPTGEN_RESULT: OK" >> "$OUT/cryptgen_wine.txt"
else
  echo "CRYPTGEN_RESULT: NOT_RUN_UNDER_WINE" >> "$OUT/cryptgen_wine.txt"
fi
