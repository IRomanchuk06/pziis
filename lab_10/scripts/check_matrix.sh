#!/bin/bash
# check_matrix.sh — шаг 14 задания: для КАЖДОГО созданного файла проверить,
# можно ли прочитать, редактировать и запустить его от имени
# iit11, iit12, iit21, iit22, iit3 и суперпользователя (root).
# Результат — текстовая таблица OK/DENIED -> demo_output/matrix.txt
# (полный журнал команд -> demo_output/matrix_detail.txt).
set -u
. /opt/lab/scripts/common.sh

RES=/tmp/lab10_matrix
MTX=$DEMO/matrix.txt
DET=$DEMO/matrix_detail.txt

rm -rf "$RES"; mkdir -p "$RES"; chmod 777 "$RES"
: > "$MTX"; : > "$DET"

banner "Шаг 14. Матрица доступа к файлам (чтение / редактирование / запуск)"
echo "Объём: 4 каталога (pzs11-pzs14) x 25 файлов x 6 субъектов x 3 операции = 1800 проверок."
echo "Реальные команды: чтение = cat; редактирование = echo >>; запуск = ./файл </dev/null."

for d in $DIRS; do
  for u in $TEST_USERS; do
    res="$RES/${d}__${u}.res"
    rm -f "$res"
    if [ "$u" = root ]; then
      bash "$SCRIPTS/inner_matrix.sh" "$d" "$res"
    else
      as_user "$u" "bash $SCRIPTS/inner_matrix.sh $d $res"
    fi
    {
      echo "### dir=$d user=$u"
      cat "$res"
    } >> "$DET"
  done
  echo "  каталог $d проверен."
done

# ---------- сборка таблицы ----------
{
  echo "МАТРИЦА ДОСТУПА К ФАЙЛАМ (шаг 14; результаты реальных команд)"
  echo
  echo "Субъекты: iit11, iit12 (group_iit1); iit21 (group_iit2, администратор/sudo);"
  echo "          iit22 (group_iit2); iit3; root (суперпользователь)."
  echo "Объекты : file11-file55 в каталогах pzs11-pzs14."
  echo "          file11-file45 созданы iit11 (группа group_iit1);"
  echo "          file51-file55 созданы от администратора (root:root)."
  echo "Ячейка R W X : R = cat (чтение), W = echo >> (редактирование), X = ./файл (запуск)."
  echo "Обозначения  : + = OK (операция выполнена), - = DENIED (доступ запрещён)."

  total_ok=0
  total_den=0
  for d in $DIRS; do
    echo
    echo "=== $PZS/$d — $(mode_of "$PZS/$d"), владелец $(stat -c '%U:%G' "$PZS/$d") ==="
    printf '%-8s %-12s %-16s' "файл" "права" "влад:группа"
    for u in $TEST_USERS; do printf ' %-6s' "$u"; done
    echo
    printf '%-8s %-12s %-16s' "" "" ""
    for _ in $TEST_USERS; do printf ' %-6s' "R W X"; done
    echo

    declare -A S
    for u in $TEST_USERS; do
      while IFS='|' read -r f op st _rc _err; do
        S["$u|$f|$op"]=$st
      done < "$RES/${d}__${u}.res"
    done

    for n in $FILE_NUMS; do
      f="file$n"
      fm=$(stat -c '%A' "$PZS/$d/$f" 2>/dev/null)
      fo=$(stat -c '%U:%G' "$PZS/$d/$f" 2>/dev/null)
      printf '%-8s %-12s %-16s' "$f" "$fm ($(pad_oct "$(stat -c '%a' "$PZS/$d/$f")"))" "$fo"
      for u in $TEST_USERS; do
        cell=""
        for op in read edit exec; do
          st=${S["$u|$f|$op"]:-MISSING}
          if [ "$st" = OK ]; then
            cell+='+'
            total_ok=$((total_ok+1))
          else
            cell+='-'
            total_den=$((total_den+1))
          fi
        done
        printf ' %-6s' "$cell"
      done
      echo
    done
    unset S
  done

  echo
  echo "Итого проверок: $((total_ok+total_den)); разрешено (OK) = $total_ok; запрещено (DENIED) = $total_den."

  echo
  echo "Дополнительно — административные привилегии iit21 (шаг 4 задания):"
  echo -n "  чтение file51 (root:root, 400) в pzs14 от iit21 напрямую : "
  if as_user "$ADMIN" "cat $PZS/pzs14/file51" >/dev/null 2>&1; then echo "OK"; else echo "DENIED"; fi
  echo -n "  чтение file51 (root:root, 400) в pzs14 от iit21 через sudo: "
  if as_user "$ADMIN" "sudo -n cat $PZS/pzs14/file51" >/dev/null 2>&1; then echo "OK"; else echo "DENIED"; fi
  echo -n "  ls pzs15 (root:root, 700) от iit21 напрямую : "
  if as_user "$ADMIN" "ls $PZS/pzs15" >/dev/null 2>&1; then echo "OK"; else echo "DENIED"; fi
  echo -n "  ls pzs15 (root:root, 700) от iit21 через sudo: "
  if as_user "$ADMIN" "sudo -n ls $PZS/pzs15" >/dev/null 2>&1; then echo "OK"; else echo "DENIED"; fi
} > "$MTX"

echo
cat "$MTX"
rm -rf "$RES"
