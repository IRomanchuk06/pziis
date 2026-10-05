#!/bin/bash
# inner_matrix.sh — выполняется ОТ ИМЕНИ проверяемого пользователя:
#   bash inner_matrix.sh <pzsXX> <файл_результатов>
# Для каждого файла file11-file55 выполняет реальные команды:
#   чтение        : cat <файл>
#   редактирование: printf '...\n' >> <файл>
#   запуск        : ./<файл> </dev/null
# и записывает результат каждой операции в файл результатов:
#   <файл>|<операция>|OK|DENIED|<код возврата>|<первая строка stderr>
set -u
. /opt/lab/scripts/common.sh

d=$1
res=$2
dirpath=$PZS/$d
: > "$res"

# классификация запуска: скрипт реально выполнился -> rc 0
# (echo) или rc 1 (filex5 завершился на EOF команды read);
# rc 126/127 и "Permission denied" -> запуск запрещён.
exec_check() {
  local out rc st
  out=$(./"$1" </dev/null 2>&1)
  rc=$?
  case $rc in
    0) st=OK ;;
    1)
      case "$out" in
        *Permission\ denied*) st=DENIED ;;
        *) st=OK ;;
      esac ;;
    *) st=DENIED ;;
  esac
  EMIT_ST=$st
  EMIT_RC=$rc
  EMIT_ERR=$(printf '%s' "$out" | head -1 | cut -c1-55)
}

emit() { # emit <файл> <операция> <статус> <rc> <stderr>
  printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" >> "$res"
}

# Для входа в каталог нужен бит x на всём пути (pzs и pzsXX)
can_cd=1
cd "$dirpath" 2>/dev/null || can_cd=0
CD_ERR="cd: $dirpath: Permission denied"

for n in $FILE_NUMS; do
  f="file$n"
  if [ "$can_cd" = 0 ]; then
    emit "$f" read DENIED - "$CD_ERR"
    emit "$f" edit DENIED - "$CD_ERR"
    emit "$f" exec DENIED - "$CD_ERR"
    continue
  fi

  # чтение
  err=$(cat "$f" 2>&1 >/dev/null); rc=$?
  [ $rc -eq 0 ] && st=OK || st=DENIED
  emit "$f" read "$st" "$rc" "$(printf '%s' "$err" | head -1 | cut -c1-55)"

  # редактирование (дозапись). Дописывается строка-КОММЕНТАРИЙ: проверка
  # остаётся реальной записью в файл, но не меняет поведение сценария
  # при последующей проверке запуска в этой же итерации.
  err=$(printf '# edit check by %s\n' "$(id -un)" >> "$f" 2>&1); rc=$?
  [ $rc -eq 0 ] && st=OK || st=DENIED
  emit "$f" edit "$st" "$rc" "$(printf '%s' "$err" | head -1 | cut -c1-55)"

  # запуск
  exec_check "$f"
  emit "$f" exec "$EMIT_ST" "$EMIT_RC" "$EMIT_ERR"
done
