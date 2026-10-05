#!/usr/bin/env bash
# Лабораторная работа № 4. Прогон анализов «Expert» и доп. тестов + сводная таблица.
# Вызывается из demo.sh; повторно вызывается из wine_run.sh, когда появляется
# файл CryptGenRandom (demo_output/data/crypt_out.bin).
set -uo pipefail
cd /work

OUT=demo_output
export PYTHONDONTWRITEBYTECODE=1  # не оставлять __pycache__ в примонтированной папке

{
  echo "=== Программа «Expert»: критерий хи-квадрат (256 ст. св.) ==="
  python3 tools/expert.py \
      "$OUT/data/msvc_rand.bin" \
      "$OUT/data/own_gen.bin" \
      "$OUT/data/urandom.bin" \
      bin/gen_own \
      bin/gen_crypt.exe \
      "$OUT/data/archive.zip" \
      $([ -f "$OUT/data/crypt_out.bin" ] && echo "$OUT/data/crypt_out.bin")
} 2>&1 | tee "$OUT/expert_results.txt"

{
  echo "=== Дополнительные простые тесты (частотный, пар байтов, longest run) ==="
  python3 tools/extra_tests.py \
      "$OUT/data/msvc_rand.bin" \
      "$OUT/data/own_gen.bin" \
      "$OUT/data/urandom.bin" \
      $([ -f "$OUT/data/crypt_out.bin" ] && echo "$OUT/data/crypt_out.bin")
} 2>&1 | tee "$OUT/extra_tests.txt"

python3 tools/make_table.py > "$OUT/summary_table.md" 2>&1 \
  && echo "summary_table: OK ($OUT/summary_table.md)"
