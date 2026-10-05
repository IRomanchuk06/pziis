#!/bin/bash
# inner_create_root.sh — вызывается от имени АДМИНИСТРАТОРА
# (iit21 через sudo, фактически root):
#   bash inner_create_root.sh <pzsXX>
# Создаёт file51-file55 («только для администратора»), владелец root:root.
set -u
. /opt/lab/scripts/common.sh

d=$1
cd "$PZS/$d" || { echo "inner_create_root: нет доступа к $PZS/$d" >&2; exit 1; }

declare -A PERMS=(
  [file51]=400 [file52]=600 [file53]=200 [file54]=700 [file55]=100
)

for n in 51 52 53 54 55; do
  f="file$n"
  case "$f" in
    file55)  # шаблон filex5: «read testVariable»
      printf '#!/bin/bash\nread testVariable\n' > "$f" ;;
    *)
      printf '#!/bin/bash\necho "Hello World"\n' > "$f" ;;
  esac
  chown root:root "$f"
  chmod "${PERMS[$f]}" "$f"
done
echo "  создано 5 файлов (file51-file55), владелец $(id -un):$(id -gn)"
