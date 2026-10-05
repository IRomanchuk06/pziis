#!/usr/bin/env bash
# Лабораторная работа 6 «Применение OpenSSL».
# Выполняется ВНУТРИ контейнера (ubuntu:24.04 + openssl из apt).
# Результат каждого шага пишется в /output (на хосте -- demo_output/).

set -u

OUT=/output
WORK="$(mktemp -d)"
FULL="$OUT/lab6_full_log.txt"
mkdir -p "$OUT"
cd "$WORK"
: > "$FULL"

# ------------------------- параметры демо -------------------------
SYM_PASS='lab6-secret-passphrase'
PBKDF2_ITER=10000
KEY256='00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
DES3KEY='00112233445566778899aabbccddeeff0011223344556677'              # 24 байта
RC4KEY='00112233445566778899aabbccddeeff'                              # 16 байт
IVHEX='0102030405060708090a0b0c0d0e0f10'                               # 16 байт
BIN_SIZE=$((4 * 1024 * 1024))   # 4 МиБ -- бинарный файл для замеров

# ------------------------- вспомогательные ------------------------
divider() { echo "=============================================================="; }

timed() {
  # timed "<описание>" <команда...>: выполняет команду, печатает время (мс)
  local desc="$1"; shift
  local t0 t1 rc
  t0=$(date +%s%N)
  "$@"
  rc=$?
  t1=$(date +%s%N)
  awk -v d=$((t1 - t0)) -v desc="$desc" -v rc="$rc" \
    'BEGIN { printf "   [%s] время: %.2f мс (код возврата %d)\n", desc, d/1000000, rc }'
  return "$rc"
}

do_section() {
  # do_section <файл> <заголовок> <функция>: вывод функции пишется
  # одновременно в отдельный файл секции и в общий лог
  local fname="$1" title="$2" fn="$3"
  {
    divider
    echo "-- $title"
    divider
    "$fn"
    echo
  } 2>&1 | tee "$OUT/$fname" | tee -a "$FULL"
}

probe_cipher() {
  # Доступность симметричного шифра для `openssl enc`:
  # печатает "" (default provider), "legacy" (нужен legacy provider)
  # или "UNAVAILABLE".
  local c="$1"
  if echo x | openssl enc "-$c" -e -pass pass:t -pbkdf2 >/dev/null 2>&1; then
    echo ""
  elif echo x | openssl enc "-$c" -e -pass pass:t -pbkdf2 \
        -provider legacy -provider default >/dev/null 2>&1; then
    echo "legacy"
  else
    echo "UNAVAILABLE"
  fi
}

# ------------------------- подготовка файлов ----------------------
prepare_files() {
  cat > file.txt <<'EOT'
BSUIR, lab 6: OpenSSL demo file.
Line 2: symmetric and asymmetric encryption test.
Line 3: 2026.
EOT
  echo "Текстовый файл file.txt ($(stat -c %s file.txt) байт):"
  cat file.txt
  echo
  head -c "$BIN_SIZE" /dev/urandom > file.bin
  echo "Бинарный файл file.bin: $(stat -c %s file.bin) байт случайных данных из /dev/urandom"
}

# ------------------------- шаг 1 ----------------------------------
section_overview() {
  echo
  echo "\$ openssl version"
  openssl version
  echo
  echo "\$ openssl version -a (сокращено)"
  openssl version -a | head -n 6
  echo
  echo "\$ openssl help (список стандартных команд, первые 40 строк)"
  openssl help 2>&1 | head -n 40
  echo "    ... (вывод сокращён)"
  echo
  echo "\$ openssl list -cipher-algorithms (первые 25 строк)"
  openssl list -cipher-algorithms 2>&1 | head -n 25
  echo "    ... (вывод сокращён)"
  echo
  echo "\$ openssl list -digest-algorithms (первые 15 строк)"
  openssl list -digest-algorithms 2>&1 | head -n 15
  echo "    ... (вывод сокращён)"
  echo
  echo "\$ openssl list -public-key-algorithms (первые 12 строк)"
  openssl list -public-key-algorithms 2>&1 | head -n 12
  echo "    ... (вывод сокращён)"
}

# ------------------------- шаг 2 ----------------------------------
speed_one() {
  local alg="$1"
  echo "\$ openssl speed -seconds 1 -elapsed $alg"
  if openssl speed -seconds 1 -elapsed "$alg" 2>&1; then
    :
  else
    echo "  --> алгоритм '$alg' не поддерживается openssl speed в данной сборке -- пропуск"
  fi
  echo
}

section_speed() {
  echo
  echo "Тест: openssl speed, -seconds 1 (1 секунда на алгоритм),"
  echo "-elapsed -- замер по прошедшему (wall-clock) времени."
  echo
  echo "Примечание: aes-*-gcm и chacha20 в 'openssl speed' сборки 3.0.x"
  echo "не поддерживаются (проверено: 'speed: Unknown algorithm'), поэтому"
  echo "для сравнения AES-128 взят режим CBC."
  echo
  for a in aes-256-cbc aes-128-cbc chacha20 chacha20-poly1305 sha256 rsa2048; do
    speed_one "$a"
  done
  echo "-- Дополнительно: ed25519 (электронная подпись) --"
  echo
  speed_one ed25519
}

# ------------------------- шаг 3a ---------------------------------
sym_round() {
  local c="$1"
  local probe
  probe="$(probe_cipher "$c")"
  echo
  echo "--- Шифр: $c ---"
  if [ "$probe" = "UNAVAILABLE" ]; then
    echo "  Результат: шифр '$c' недоступен в данной сборке OpenSSL (проверено openssl enc). Пропуск."
    return 0
  fi
  local prov=()
  if [ "$probe" = "legacy" ]; then
    prov=(-provider legacy -provider default)
    echo "  (алгоритм доступен через legacy provider)"
  fi

  # 1) функциональный прогон: пароль + PBKDF2 + соль (текстовый файл)
  if openssl enc "-$c" -e -in file.txt -out "f.txt.$c.enc" \
       -pass pass:"$SYM_PASS" -pbkdf2 -iter $PBKDF2_ITER -salt "${prov[@]}"; then
    echo "  шифрование file.txt: OK ($(stat -c %s "f.txt.$c.enc") байт)"
  else
    echo "  шифрование file.txt: ОШИБКА"
    return 0
  fi
  if openssl enc "-$c" -d -in "f.txt.$c.enc" -out "f.txt.$c.dec" \
       -pass pass:"$SYM_PASS" -pbkdf2 -iter $PBKDF2_ITER "${prov[@]}"; then
    echo "  расшифрование: OK ($(stat -c %s "f.txt.$c.dec") байт)"
  else
    echo "  расшифрование: ОШИБКА"
    return 0
  fi
  if cmp -s file.txt "f.txt.$c.dec"; then
    echo "  cmp: расшифрованный файл побитово совпадает с исходным"
  else
    echo "  cmp: ФАЙЛЫ РАЗЛИЧАЮТСЯ -- ОШИБКА!"
  fi
  echo "  Заголовок криптограммы (магия 'Salted__' + соль):"
  od -A d -t x1z -N 32 "f.txt.$c.enc" | head -n 3

  # 2) замер времени на бинарном файле 4 МиБ с фиксированным ключом (без KDF)
  local keyhex ivargs=()
  case "$c" in
    des3) keyhex="$DES3KEY"; ivargs=(-iv "$IVHEX") ;;
    rc4)  keyhex="$RC4KEY" ;;   # потоковый шифр: IV не используется
    *)    keyhex="$KEY256"; ivargs=(-iv "$IVHEX") ;;
  esac
  timed "шифрование file.bin 4МиБ ($c)" \
    openssl enc "-$c" -e -in file.bin -out "f.bin.$c.enc" -K "$keyhex" "${ivargs[@]}" "${prov[@]}"
  timed "расшифрование file.bin 4МиБ ($c)" \
    openssl enc "-$c" -d -in "f.bin.$c.enc" -out "f.bin.$c.dec" -K "$keyhex" "${ivargs[@]}" "${prov[@]}"
  if cmp -s file.bin "f.bin.$c.dec"; then
    echo "   cmp бинарника после цикла шифр/дешифр: OK"
  else
    echo "   cmp бинарника: ОШИБКА!"
  fi
}

section_symmetric() {
  echo
  echo "Файлы: file.txt ($(stat -c %s file.txt) байт), file.bin ($(stat -c %s file.bin) байт)."
  echo "Функциональный прогон -- с паролем и PBKDF2 (итераций: $PBKDF2_ITER),"
  echo "замеры времени -- на file.bin с фиксированным ключом (без KDF)."
  echo
  for c in aes-256-cbc camellia-256-cbc des3 rc4; do
    sym_round "$c"
  done
  echo
  echo "Примечание: aes-256-gcm НЕ поддерживается командой 'openssl enc':"
  echo "AEAD-режимы в enc запрещены (нет обработки аутентификационного тега),"
  echo "производительность GCM измерена на шаге 2 (openssl speed)."
}

# ------------------------- шаг 3b ---------------------------------
section_asymmetric() {
  echo
  echo "== RSA-2048: зашифрование/расшифрование малого файла =="
  echo
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_priv.pem 2>/dev/null
  echo "Сгенерирован приватный ключ rsa_priv.pem ($(stat -c %s rsa_priv.pem) байт)."
  openssl pkey -in rsa_priv.pem -pubout -out rsa_pub.pem
  echo "Извлечён открытый ключ rsa_pub.pem ($(stat -c %s rsa_pub.pem) байт)."
  echo "Публичные параметры ключа:"
  openssl pkey -in rsa_pub.pem -pubin -text_pub -noout
  echo
  cat > small.txt <<'EOT'
Secret message for RSA encryption demo!
EOT
  echo "Исходный файл small.txt: \"$(cat small.txt)\" ($(stat -c %s small.txt) байт)"
  timed "RSA-2048-OAEP(sha256) зашифрование" \
    openssl pkeyutl -encrypt -pubin -inkey rsa_pub.pem -in small.txt -out small.txt.enc \
      -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
  echo "   Криптограмма small.txt.enc: $(stat -c %s small.txt.enc) байт"
  timed "RSA-2048-OAEP(sha256) расшифрование" \
    openssl pkeyutl -decrypt -inkey rsa_priv.pem -in small.txt.enc -out small.txt.dec \
      -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
  if cmp -s small.txt small.txt.dec; then
    echo "   cmp: расшифровано верно, текст совпадает с исходным"
  else
    echo "   cmp: ОШИБКА расшифрования"
  fi

  echo
  echo "== Ограничение RSA: попытка зашифровать 300 байт (ожидаемая ошибка) =="
  echo
  head -c 300 /dev/urandom > too_big.bin
  echo "Файл too_big.bin: $(stat -c %s too_big.bin) байт."
  if openssl pkeyutl -encrypt -pubin -inkey rsa_pub.pem -in too_big.bin -out too_big.enc \
       -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 2>rsa_err.txt; then
    echo "Неожиданно: шифрование прошло успешно."
  else
    echo "Получена ОЖИДАЕМАЯ ошибка (данные длиннее максимума для RSA-2048+OAEP(SHA-256) = 190 байт):"
    sed 's/^/    /' rsa_err.txt
  fi

  echo
  echo "== Ed25519: электронная подпись файла =="
  echo
  openssl genpkey -algorithm ED25519 -out ed_priv.pem
  openssl pkey -in ed_priv.pem -pubout -out ed_pub.pem
  echo "Сгенерирована пара ключей Ed25519 (ed_priv.pem / ed_pub.pem)."
  echo "Публичный ключ:"
  openssl pkey -in ed_pub.pem -pubin -text_pub -noout
  # Ed25519 -- PureEdDSA: подписывается сырой файл, обязателен -rawin.
  # В OpenSSL 3.0.x 'openssl dgst' не поддерживает -rawin (появился в 3.1.1),
  # поэтому подписываем через pkeyutl.
  if openssl pkeyutl -sign -rawin -inkey ed_priv.pem -in file.txt -out file.txt.sig; then
    echo "Подпись файла file.txt -> file.txt.sig ($(stat -c %s file.txt.sig) байт)."
  else
    echo "ОШИБКА: создать подпись не удалось"
  fi
  timed "Ed25519: создание подписи" \
    openssl pkeyutl -sign -rawin -inkey ed_priv.pem -in file.txt -out file.txt.sig
  timed "Ed25519: проверка подписи" \
    openssl pkeyutl -verify -rawin -pubin -inkey ed_pub.pem -sigfile file.txt.sig -in file.txt
}

# ------------------------- шаг 3c ---------------------------------
section_hashes() {
  local f
  for f in file.txt file.bin; do
    echo
    echo "-- Файл: $f ($(stat -c %s "$f") байт) --"
    echo
    echo "\$ openssl dgst -md5 $f"
    openssl dgst -md5 "$f"
    echo
    echo "\$ openssl dgst -sha1 $f"
    openssl dgst -sha1 "$f"
    echo
    echo "\$ openssl dgst -sha256 $f"
    openssl dgst -sha256 "$f"
  done
  echo
  echo "-- Перекрёстная проверка: openssl dgst -sha256 против утилиты sha256sum --"
  echo "  openssl  : $(openssl dgst -sha256 file.bin | awk '{print $NF}')"
  echo "  sha256sum: $(sha256sum file.bin | awk '{print $1}')"
  if [ "$(openssl dgst -sha256 file.bin | awk '{print $NF}')" = \
       "$(sha256sum file.bin | awk '{print $1}')" ]; then
    echo "  Результат: хэши совпадают"
  else
    echo "  Результат: РАСХОЖДЕНИЕ!"
  fi
}

# ------------------------- шаг 4 ----------------------------------
section_cert() {
  echo
  echo "== Создание самоподписанного сертификата X.509 (RSA-2048, 365 дней) =="
  echo
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout server.key -out server.crt \
    -subj "/C=BY/ST=Minsk/L=Minsk/O=BSUIR/OU=PZIIS Lab6/CN=lab6.bsuir.local" \
    -addext "subjectAltName=DNS:lab6.bsuir.local,DNS:www.lab6.bsuir.local" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "basicConstraints=critical,CA:FALSE"
  echo "Созданы: server.crt (сертификат), server.key (приватный ключ, без пароля: -nodes)."
  echo
  echo "\$ openssl x509 -in server.crt -text -noout"
  openssl x509 -in server.crt -text -noout
  echo
  echo "\$ openssl x509: краткая сводка полей"
  openssl x509 -in server.crt -noout -subject -issuer -serial -dates -fingerprint -sha256
  echo
  echo "\$ openssl verify -CAfile server.crt server.crt (проверка цепочки)"
  openssl verify -CAfile server.crt server.crt
}

# ------------------------- запуск ---------------------------------
{
  divider
  echo "-- Подготовка исходных файлов"
  divider
  prepare_files
  echo
} 2>&1 | tee "$OUT/files.txt" | tee -a "$FULL"

do_section overview.txt   "ШАГ 1. Знакомство с OpenSSL: версия, команды, алгоритмы" section_overview
do_section speed.txt      "ШАГ 2. Тестирование скорости (openssl speed, -seconds 1)" section_speed
do_section symmetric.txt  "ШАГ 3a. Симметричное шифрование/расшифрование файлов"     section_symmetric
do_section asymmetric.txt "ШАГ 3b. Асимметричное шифрование (RSA) и подпись (Ed25519)" section_asymmetric
do_section hashes.txt     "ШАГ 3c. Хэширование файлов (md5, sha1, sha256)"           section_hashes
do_section cert.txt       "ШАГ 4. Самоподписанный сертификат X.509 и его состав"     section_cert

echo "Все шаги завершены. Результаты: $OUT (на хосте -- demo_output/)."
