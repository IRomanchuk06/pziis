#!/bin/bash
# setup.sh — шаги 1-11 задания: группы, пользователи, административные
# привилегии iit21, каталог pzs и подпапки pzs11-pzs15 с точными правами.
set -u
. /opt/lab/scripts/common.sh

banner "Шаг 1. Создание групп пользователей $GROUP1 и $GROUP2"
getent group "$GROUP1" >/dev/null || groupadd "$GROUP1"
getent group "$GROUP2" >/dev/null || groupadd "$GROUP2"
getent group "$GROUP1"
getent group "$GROUP2"

banner "Шаги 2-3, 5. Создание пользователей"
# iit11, iit12 -> основная группа group_iit1 (файлы, созданные ими, получают
# группу group_iit1 — это необходимо для сценариев «права только для группы»)
id iit11 >/dev/null 2>&1 || useradd -m -s /bin/bash -g "$GROUP1" iit11
id iit12 >/dev/null 2>&1 || useradd -m -s /bin/bash -g "$GROUP1" iit12
# iit21, iit22 -> основная группа group_iit2
id iit21 >/dev/null 2>&1 || useradd -m -s /bin/bash -g "$GROUP2" iit21
id iit22 >/dev/null 2>&1 || useradd -m -s /bin/bash -g "$GROUP2" iit22
# iit3 — обычный пользователь без специальных групп
id iit3  >/dev/null 2>&1 || useradd -m -s /bin/bash iit3
getent passwd iit11 iit12 iit21 iit22 iit3
echo "--- домашние каталоги:"; ls -la /home/
echo "--- группы:"; id iit11; id iit12; id iit21; id iit22; id iit3

banner "Шаг 4. Административные привилегии для $ADMIN (группа sudo + NOPASSWD)"
usermod -aG sudo "$ADMIN"
echo "$ADMIN ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$ADMIN"
chmod 440 "/etc/sudoers.d/$ADMIN"
visudo -c
id "$ADMIN"
echo "--- проверка: su - $ADMIN -c 'sudo -n whoami' =>"
as_user "$ADMIN" "sudo -n whoami"

banner "Шаг 6. Создание папки pzs"
mkdir -p "$PZS"
chmod 755 "$PZS"
stat -c '%A %U:%G %n' "$PZS"

banner "Шаги 7-11. Подпапки pzs11-pzs15 с правами R/W/X по заданию"
mkdir -p "$PZS"/pzs11 "$PZS"/pzs12 "$PZS"/pzs13 "$PZS"/pzs14 "$PZS"/pzs15

# pzs11 — чтение/запись/выполнение ТОЛЬКО владельцу. Владелец — iit11.
chown iit11:$GROUP1 "$PZS"/pzs11; chmod 700 "$PZS"/pzs11
# pzs12 — только для ГРУППЫ. Владелец root, группа group_iit1: члены группы
# (iit11, iit12) получают доступ через групповые биты (070).
chown root:$GROUP1 "$PZS"/pzs12; chmod 070 "$PZS"/pzs12
# pzs13 — только для ОСТАЛЬНЫХ. Владелец и группа root, поэтому все обычные
# пользователи (iit11..iit3) попадают в класс «остальные» (007).
chown root:root "$PZS"/pzs13; chmod 007 "$PZS"/pzs13
# pzs14 — для ВСЕХ пользователей.
chown iit11:$GROUP1 "$PZS"/pzs14; chmod 777 "$PZS"/pzs14
# pzs15 — только для администратора (root).
chown root:root "$PZS"/pzs15; chmod 700 "$PZS"/pzs15

ls -la "$PZS"
echo
echo "Сводка (права/владелец/группа):"
for d in $ALL_DIRS; do
  printf '  %-6s %s  %s\n' "$d" "$(mode_of "$PZS/$d")" "$(stat -c '%U:%G' "$PZS/$d")"
done
