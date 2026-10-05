#!/bin/bash
# inner_dirs.sh — выполняется ОТ ИМЕНИ проверяемого пользователя:
#   bash inner_dirs.sh <pzsXX> <метка_пользователя> <файл_результатов>
# Проверяет три операции над каталогом (шаг 16 задания):
#   чтение содержимого : ls <каталог>
#   создание файла     : touch <каталог>/create_check_<метка>
#   удаление файлов    : rm <каталог>/file11 ... file55 (+ созданный файл)
set -u
. /opt/lab/scripts/common.sh

d=$1
tag=$2
res=$3
dirpath=$PZS/$d
: > "$res"

# 1) чтение содержимого каталога
err=$(ls "$dirpath" 2>&1 >/dev/null); rc=$?
[ $rc -eq 0 ] && st=OK || st=DENIED
printf 'ls|%s|%s|%s\n' "$st" "$rc" "$(printf '%s' "$err" | head -1 | cut -c1-55)" >> "$res"

# 2) создание нового файла
if err=$(touch "$dirpath/create_check_$tag" 2>&1); then st=OK; else st=DENIED; fi
printf 'create|%s|%s|%s\n' "$st" "$?" "$(printf '%s' "$err" | head -1 | cut -c1-55)" >> "$res"

# 3) удаление каждого существующего файла (известные имена file11-file55
#    плюс файл, созданный на шаге 2). Ошибка «No such file» означает, что
#    файла в этой папке нет (например pzs15) — это не отказ в доступе.
del_ok=0; del_den=0; del_abs=0; del_err=""
try_rm() {
  local err
  if err=$(rm "$1" 2>&1); then
    del_ok=$((del_ok+1))
  else
    case "$err" in
      *"No such file"*)
        del_abs=$((del_abs+1)) ;;
      *)
        del_den=$((del_den+1))
        [ -z "$del_err" ] && del_err=$(printf '%s' "$err" | head -1 | cut -c1-55) ;;
    esac
  fi
}
for n in $FILE_NUMS; do
  try_rm "$dirpath/file$n"
done
try_rm "$dirpath/create_check_$tag"
printf 'delete|%s|%s|%s|%s\n' "$del_ok" "$del_den" "$del_abs" "$del_err" >> "$res"
