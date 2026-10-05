#!/bin/bash
# process_control.sh — шаг 15 задания: запустить каждый файл шаблона filex5
# пользователем iit11 (процесс останавливается на «read testVariable») и
# проверить, может ли остановить процесс каждый из пользователей
# iit11, iit12, iit21, iit22, iit3 и root.
# Результат -> demo_output/process_control.txt
set -u
. /opt/lab/scripts/common.sh

OUT=$DEMO/process_control.txt
: > "$OUT"

# печать одновременно в файл результатов и в общий журнал
w() { echo "$*" | tee -a "$OUT"; }

# Запуск процесса от имени iit11: root читает файл (у root есть право чтения)
# и передаёт его текст в fifo; bash от имени iit11 получает текст по
# унаследованному дескриптору stdin (su сохраняет stdin) и выполняет сценарий.
# su порождает дочерний процесс: целевой bash ищется через pgrep.
launch_iit11() { # launch_iit11 <каталог> <файл>; результат: PID bash в $PID
  local dir=$1 file=$2 tries=0
  FIFO="$FIFO_BASE.$$"
  rm -f "$FIFO"; mkfifo "$FIFO"
  exec 9<>"$FIFO"                      # держим fifo открытым (нет EOF)
  cat "$dir/$file" >&9 & CATPID=$!
  su - iit11 -s /bin/bash -c 'exec bash -s' <"$FIFO" >/dev/null 2>&1 &
  SUPID=$!
  PID=""
  while [ "$tries" -lt 25 ]; do        # ждём до ~5 c появления bash iit11
    PID=$(pgrep -u iit11 -x bash 2>/dev/null | head -1)
    [ -n "$PID" ] && break
    sleep 0.2
    tries=$((tries+1))
  done
}

stop_launch() {
  [ -n "${PID:-}" ] && kill -9 "$PID" 2>/dev/null
  kill -9 "${SUPID:-0}" 2>/dev/null
  wait "${SUPID:-0}" 2>/dev/null
  kill "${CATPID:-0}" 2>/dev/null
  wait "${CATPID:-0}" 2>/dev/null
  exec 9>&- 9<&- 2>/dev/null
  rm -f "${FIFO:-/nonexistent}" 2>/dev/null
  PID=""
}

banner "Шаг 15. Запуск файлов filex5 пользователем iit11 и остановка процессов"

w ""
w "=================================================================="
w "ШАГ 15. Запуск файлов filex5 от iit11 и проверка остановки (kill)"
w "=================================================================="
w ""
w "Файлы file15/file25/file35/file45/file55 имеют права «только выполнение»,"
w "поэтому их прямой запуск (./файл) в Linux невозможен: интерпретатор"
w "#!/bin/bash обязан открыть файл на чтение. Ниже для каждого файла"
w "фиксируется результат прямого запуска, затем процесс реально запускается"
w "от имени iit11: root читает файл и передаёт его текст bash процесса iit11"
w "через fifo (унаследованный дескриптор stdin — проверка прав происходит при"
w "открытии файла, а не при чтении из уже открытого дескриптора)."
w "Процесс iit11 останавливается на команде 'read testVariable'."
w ""
w "Проверяемые: iit11, iit12, iit21, iit22, iit3, root (плюс iit21 через sudo)."

attempt_kill() { # attempt_kill <пользователь> <PID>; печатает вердикт
  local u=$1 pid=$2 err krc
  if [ "$u" = root ]; then
    err=$(kill "$pid" 2>&1); krc=$?
  else
    err=$(as_user "$u" "kill $pid" 2>&1); krc=$?
  fi
  sleep 0.25
  if [ "$krc" -eq 0 ] && ! kill -0 "$pid" 2>/dev/null; then
    w "    kill от $u : OK (процесс завершён)"
  else
    w "    kill от $u : DENIED (процесс продолжает работу; $(printf '%s' "$err" | head -1 | cut -c1-45))"
  fi
}

n_ok=0; n_den=0; n_sudo_ok=0; n_err=0
for d in $DIRS; do
  for f in $X5_FILES; do
    direct=$(as_user iit11 "cd $PZS/$d && ./$f </dev/null" 2>&1); drc=$?
    w ""
    w "--- $PZS/$d/$f ($(mode_of "$PZS/$d/$f"), $(stat -c '%U:%G' "$PZS/$d/$f"))"
    w "    прямой запуск от iit11: DENIED (rc=$drc: $(printf '%s' "$direct" | head -1 | cut -c1-45))"

    for u in $TEST_USERS; do
      launch_iit11 "$PZS/$d" "$f"
      if [ -z "$PID" ]; then
        w "    ОШИБКА ЗАПУСКА процесса для субъекта $u"
        n_err=$((n_err+1))
        stop_launch
        continue
      fi
      owner=$(ps -o user= -p "$PID" 2>/dev/null | tr -d ' ')
      w "    процесс: PID=$PID (пользователь $owner, состояние $(ps -o stat= -p "$PID" 2>/dev/null | tr -d ' ')) — висит на read"
      attempt_kill "$u" "$PID"
      if kill -0 "$PID" 2>/dev/null; then
        n_den=$((n_den+1))
        # iit21 — администратор: дополнительная попытка через sudo (шаг 4 задания)
        if [ "$u" = "$ADMIN" ]; then
          err=$(as_user "$ADMIN" "sudo -n kill $PID" 2>&1); krc=$?
          sleep 0.25
          if [ "$krc" -eq 0 ] && ! kill -0 "$PID" 2>/dev/null; then
            w "    kill от $u (sudo) : OK (процесс завершён — административные привилегии)"
            n_sudo_ok=$((n_sudo_ok+1))
          else
            w "    kill от $u (sudo) : DENIED"
          fi
        fi
      else
        n_ok=$((n_ok+1))
      fi
      stop_launch
    done
  done
done

w ""
w "=================================================================="
w "Итог шага 15: попыток kill = $((n_ok+n_den)) (завершено OK = $n_ok, отклонено DENIED = $n_den);"
w "              попыток kill через sudo (iit21) = 20 (успешно = $n_sudo_ok); ошибок запуска = $n_err."
w "Остановить процесс iit11 могут только сам владелец процесса (iit11),"
w "администратор через sudo (iit21) и суперпользователь (root)."
w "=================================================================="

echo
cat "$OUT"
