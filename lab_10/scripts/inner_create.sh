#!/bin/bash
# inner_create.sh — вызывается ОТ ИМЕНИ iit11:
#   bash inner_create.sh <pzsXX>
# Создаёт file11-file45 в каталоге $PZS/<pzsXX> и выставляет точные права.
set -u
. /opt/lab/scripts/common.sh

d=$1
cd "$PZS/$d" || { echo "inner_create: нет доступа к $PZS/$d" >&2; exit 1; }

declare -A PERMS=(
  [file11]=400 [file12]=600 [file13]=200 [file14]=700 [file15]=100
  [file21]=040 [file22]=060 [file23]=020 [file24]=070 [file25]=010
  [file31]=004 [file32]=006 [file33]=002 [file34]=007 [file35]=001
  [file41]=444 [file42]=666 [file43]=222 [file44]=777 [file45]=111
)

for n in 11 12 13 14 15 21 22 23 24 25 31 32 33 34 35 41 42 43 44 45; do
  f="file$n"
  case "$f" in
    # файлы шаблона filex5 «висят» на read (для ОС Linux)
    file15|file25|file35|file45)
      printf '#!/bin/bash\nread testVariable\n' > "$f" ;;
    *)
      printf '#!/bin/bash\necho "Hello World"\n' > "$f" ;;
  esac
  chmod "${PERMS[$f]}" "$f"
done
echo "  создано 20 файлов (file11-file45), владелец $(id -un):$(id -gn)"
