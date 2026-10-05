#!/bin/bash
# cleanup.sh — шаг 17 задания: удалить созданные файлы, папки, пользователей
# iit11, iit12, iit21, iit22, iit3 и группы group_iit1, group_iit2.
set -u
. /opt/lab/scripts/common.sh

banner "Шаг 17. Очистка: файлы, папки, пользователи, группы"

echo "--- 1. Остановка оставшихся процессов пользователей"
for u in $USERS; do
  if pkill -9 -u "$u" 2>/dev/null; then
    echo "  pkill -9 -u $u: процессы остановлены"
  else
    echo "  pkill -9 -u $u: процессов нет"
  fi
done

echo "--- 2. Удаление файлов и папок (pzs, резервная копия, временные файлы)"
rm -rf "$PZS" "$BACKUP" /tmp/lab10_matrix /tmp/lab10_dirs "$FIFO_BASE"*
ls -la "$BASE"

echo "--- 3. Отзыв административных привилегий iit21"
rm -f "/etc/sudoers.d/$ADMIN"
ls -la /etc/sudoers.d/ 2>/dev/null || echo "  /etc/sudoers.d отсутствует"

echo "--- 4. Удаление пользователей (userdel -r: с домашними каталогами)"
for u in $USERS; do
  userdel -r "$u" 2>&1 | sed 's/^/  /'
done

echo "--- 5. Удаление групп"
groupdel "$GROUP1" 2>&1 | sed 's/^/  /'
groupdel "$GROUP2" 2>&1 | sed 's/^/  /'

echo "--- 6. Проверка чистоты системы"
echo -n "  getent passwd iit11 iit12 iit21 iit22 iit3: "
getent passwd $USERS | tr '\n' ' '; echo "(пусто — пользователи удалены)"
echo -n "  getent group group_iit1 group_iit2: "
getent group "$GROUP1" "$GROUP2" | tr '\n' ' '; echo "(пусто — группы удалены)"
echo -n "  /etc/sudoers.d/$ADMIN: "
[ -e "/etc/sudoers.d/$ADMIN" ] && echo "СУЩЕСТВУЕТ (ошибка!)" || echo "отсутствует"
echo -n "  каталог $PZS: "
[ -e "$PZS" ] && echo "СУЩЕСТВУЕТ (ошибка!)" || echo "удалён"
echo "  /home:"; ls -la /home/ | sed 's/^/    /'
echo "  остались процессы пользователей: "
pgrep -u "$USERS" >/dev/null 2>&1 && pgrep -a -u "$USERS" | sed 's/^/    /' || echo "    нет"
