# common.sh — общие константы и функции лабораторной работы №10.
# Подключается всеми скриптами: . /opt/lab/scripts/common.sh

BASE=/opt/lab
SCRIPTS=$BASE/scripts
PZS=$BASE/pzs
DEMO=$BASE/demo_output
BACKUP=$BASE/.dir_backup
FIFO_BASE=/tmp/lab10_fifo

# --- субъекты доступа (шаги 1-5 задания) ---
GROUP1=group_iit1
GROUP2=group_iit2
ADMIN=iit21                       # пользователь с административными привилегиями (sudo)
USERS="iit11 iit12 iit21 iit22 iit3"
# Субъекты матрицы проверок (шаг 14 задания): 5 пользователей + суперпользователь
TEST_USERS="iit11 iit12 iit21 iit22 iit3 root"

# --- объекты доступа (шаги 6-11 задания) ---
DIRS="pzs11 pzs12 pzs13 pzs14"    # каталоги, в которых создаются файлы
ALL_DIRS="pzs11 pzs12 pzs13 pzs14 pzs15"

# Порядок файлов file11..file55
FILE_NUMS="11 12 13 14 15 21 22 23 24 25 31 32 33 34 35 41 42 43 44 45 51 52 53 54 55"
# Файлы по шаблону filex5 (содержат «read testVariable»)
X5_FILES="file15 file25 file35 file45 file55"

# banner "текст" — заголовок этапа в общем журнале
banner() {
  echo
  echo "=============================================================="
  echo "== $*"
  echo "=============================================================="
}

# as_user <пользователь> <команда> — выполнить команду от имени пользователя
# (su из-под root пароля не требует; -s /bin/bash гарантирует рабочий shell)
as_user() {
  local u=$1
  shift
  su - "$u" -s /bin/bash -c "$*"
}

# pad_oct 7 -> 007 : трёхзначное восьмеричное представление прав
pad_oct() {
  local o=$1
  while [ ${#o} -lt 3 ]; do o="0$o"; done
  printf '%s' "$o"
}

# mode_of <путь> -> "drwx------ (700)"
mode_of() {
  printf '%s (%s)' "$(stat -c '%A' "$1" 2>/dev/null)" "$(pad_oct "$(stat -c '%a' "$1" 2>/dev/null)")"
}
