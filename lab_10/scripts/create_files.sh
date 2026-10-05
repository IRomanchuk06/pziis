#!/bin/bash
# create_files.sh — шаги 12-13 задания: смена текущего пользователя на iit11
# и создание файлов file11-file55 в папках pzs11-pzs14.
set -u
. /opt/lab/scripts/common.sh

banner "Шаг 12. Смена текущего пользователя на iit11"
as_user iit11 "id; echo \"HOME=\$HOME\"; pwd; whoami"

banner "Шаг 13. Создание файлов file11-file45 в папках pzs11-pzs14 (от имени iit11)"
echo "Содержимое: file15/file25/file35/file45 (шаблон filex5) -> 'read testVariable',"
echo "остальные -> 'echo \"Hello World\"'; у всех файлов строка shebang #!/bin/bash."
echo
for d in $DIRS; do
  echo "--- $d: iit11 создаёт file11-file45"
  as_user iit11 "bash $SCRIPTS/inner_create.sh $d"
done

echo
echo "--- file51-file55 («только для администратора») создаёт iit21 через sudo:"
echo "    владелец root:root, права 400/600/200/700/100."
for d in $DIRS; do
  echo "--- $d: iit21 (sudo) создаёт file51-file55"
  as_user "$ADMIN" "sudo -n bash $SCRIPTS/inner_create_root.sh $d"
done

banner "Шаг 13. Результат: права доступа созданных файлов"
for d in $DIRS; do
  echo "--- $PZS/$d ($(mode_of "$PZS/$d"), $(stat -c '%U:%G' "$PZS/$d"))"
  ls -la "$PZS/$d"
  echo
done

banner "Резервная копия каталогов (для независимых проверок удаления в шаге 16)"
rm -rf "$BACKUP"
mkdir -p "$BACKUP"
cp -a "$PZS" "$BACKUP/"
echo "Копия: $BACKUP/pzs"
ls -la "$BACKUP/pzs"
