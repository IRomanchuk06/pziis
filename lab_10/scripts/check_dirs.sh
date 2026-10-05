#!/bin/bash
# check_dirs.sh — шаг 16 задания: в каждой из созданных папок pzs11-pzs15
# проверить от имени каждого пользователя: чтение содержимого (ls),
# создание нового файла (touch) и удаление каждого существующего файла (rm).
# Чтобы проверки пользователей были независимы, после каждого субъекта
# каталог восстанавливается из резервной копии.
# Результат -> demo_output/dirs.txt
set -u
. /opt/lab/scripts/common.sh

OUT=$DEMO/dirs.txt
RES=/tmp/lab10_dirs
: > "$OUT"
rm -rf "$RES"; mkdir -p "$RES"; chmod 777 "$RES"

w() { echo "$*" | tee -a "$OUT"; }

banner "Шаг 16. Проверки операций над папками pzs11-pzs15"

w ""
w "=================================================================="
w "ШАГ 16. Операции над папками: ls (чтение содержимого),"
w "touch (создание файла), rm (удаление существующих файлов)"
w "=================================================================="
w ""
w "Субъекты: iit11, iit12, iit21, iit22, iit3, root. После каждого субъекта"
w "содержимое папки восстанавливается из резервной копии (проверки независимы)."

total_ok=0; total_den=0
for d in $ALL_DIRS; do
  w ""
  w "=== $PZS/$d — $(mode_of "$PZS/$d"), владелец $(stat -c '%U:%G' "$PZS/$d") ==="
  w "    субъект | чтение (ls) | создание (touch) | удаление (rm: OK/DENIED)"
  for u in $TEST_USERS; do
    res="$RES/${d}__${u}.res"
    if [ "$u" = root ]; then
      bash "$SCRIPTS/inner_dirs.sh" "$d" "$u" "$res"
    else
      as_user "$u" "bash $SCRIPTS/inner_dirs.sh $d $u $res"
    fi
    ls_st=$(awk -F'|' '$1=="ls"{print $2}' "$res")
    ls_err=$(awk -F'|' '$1=="ls"{print $4}' "$res")
    cr_st=$(awk -F'|' '$1=="create"{print $2}' "$res")
    cr_err=$(awk -F'|' '$1=="create"{print $4}' "$res")
    del_ok=$(awk -F'|' '$1=="delete"{print $2}' "$res")
    del_den=$(awk -F'|' '$1=="delete"{print $3}' "$res")
    del_abs=$(awk -F'|' '$1=="delete"{print $4}' "$res")
    del_err=$(awk -F'|' '$1=="delete"{print $5}' "$res")
    [ "$ls_st" = OK ] && total_ok=$((total_ok+1)) || total_den=$((total_den+1))
    [ "$cr_st" = OK ] && total_ok=$((total_ok+1)) || total_den=$((total_den+1))
    [ "$del_den" = 0 ] && total_ok=$((total_ok+1)) || total_den=$((total_den+1))
    w "    $(printf '%-7s' "$u") | $(printf '%-11s' "${ls_st}${ls_err:+ ($ls_err)}") | $(printf '%-16s' "${cr_st}${cr_err:+ ($cr_err)}") | $del_ok OK / $del_den DENIED${del_abs:+ (${del_abs} файлов в папке нет)}${del_err:+ ["$del_err"]}"
    # восстановление папки из резервной копии для следующего субъекта
    rm -rf "$PZS/$d"
    cp -a "$BACKUP/pzs/$d" "$PZS/$d"
  done
done

w ""
w "Итого операций над папками: ls + touch + rm = 6 субъектов x 5 папок x 3 операции;"
w "разрешено (OK) = $total_ok, запрещено (DENIED) = $total_den."

rm -rf "$RES"
echo
cat "$OUT"
