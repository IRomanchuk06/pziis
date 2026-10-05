#!/usr/bin/env bash
# Лабораторная работа № 4. Демонстрация внутри контейнера (compose-сервис lab4).
# Собирает C++ программы, генерирует файлы датчиков и прогоняет все анализы.
set -uo pipefail
cd /work

OUT=demo_output
mkdir -p bin "$OUT/data"
rm -f bin/gen_msvc bin/gen_own bin/gen_crypt.exe \
      "$OUT"/data/msvc_rand.bin "$OUT"/data/own_gen.bin \
      "$OUT"/data/urandom.bin "$OUT"/data/archive.zip "$OUT"/data/crypt_out.bin

{
  echo "=== Сборка C++ программ (контейнер $(hostname), $(date -u '+%Y-%m-%d %H:%M:%S UTC')) ==="
  g++ --version | head -1
  g++ -O2 -Wall -o bin/gen_msvc cpp/gen_msvc.cpp \
    && echo "build bin/gen_msvc: OK" || echo "build bin/gen_msvc: FAILED"
  g++ -O2 -Wall -o bin/gen_own cpp/gen_own.cpp \
    && echo "build bin/gen_own: OK" || echo "build bin/gen_own: FAILED"

  echo
  echo "=== Кросс-компиляция gen_crypt.exe (MinGW, CryptoAPI) ==="
  x86_64-w64-mingw32-g++ --version | head -1
  x86_64-w64-mingw32-g++ -O2 -Wall -o bin/gen_crypt.exe cpp/gen_crypt.cpp -ladvapi32 \
    && echo "build bin/gen_crypt.exe: OK" || echo "build bin/gen_crypt.exe: FAILED"
  ls -l bin/ 2>/dev/null
} 2>&1 | tee "$OUT/build.log"

{
  echo "=== Генерация файлов датчиков ==="
  echo "-- rand() как в MS VS: 20 000 000 младших байтов"
  bin/gen_msvc "$OUT/data/msvc_rand.bin" 20000000
  echo "-- Свой генератор (формула (1) табл. 1): 3 000 000 слов по 4 байта (12 МБ)"
  bin/gen_own "$OUT/data/own_gen.bin" 3000000
  echo "-- Эталон /dev/urandom: 1 МБ"
  dd if=/dev/urandom of="$OUT/data/urandom.bin" bs=1M count=1 status=none
  echo "-- Архив .zip с исходниками проекта"
  python3 tools/make_zip.py "$OUT/data/archive.zip"
  echo "-- Итоговые файлы:"
  ls -l "$OUT/data/"
} 2>&1 | tee "$OUT/generate.log"

bash scripts/run_analysis.sh
