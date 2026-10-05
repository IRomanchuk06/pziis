#!/usr/bin/env bash
# =============================================================================
# Лабораторная работа 8. Полный цикл демонстрации одной командой:
#   install (установка СУБД в Docker) ->
#   setup_access (настройка ролей/привилегий) ->
#   check_policy (проверка политики безопасности) ->
#   демонстрация отрицательных кейсов ->
#   uninstall (удаление СУБД и созданных объектов)
# Весь вывод по шагам сохраняется в demo_output/.
# Код возврата: 0 - все шаги успешны (политика корректна), != 0 - иначе.
# =============================================================================
set -u -o pipefail
cd "$(dirname "$0")"
OUT=demo_output
mkdir -p "$OUT"

banner() {
    echo
    echo "======================================================================"
    echo "== $*"
    echo "======================================================================"
}

echo "Лабораторная работа 8: Управление доступом к приложениям и системам БД"
echo "Вариант: СУБД MySQL (mysql:8.4 в Docker). Запуск: $(date '+%Y-%m-%d %H:%M:%S')"

banner "ШАГ 1/5. install.sh: установка СУБД (docker compose up) и создание БД"
bash scripts/install.sh 2>&1 | tee "$OUT/01_install.log"
install_rc=${PIPESTATUS[0]}

if [ "$install_rc" -ne 0 ]; then
    echo "ОШИБКА: установка не удалась (код $install_rc), попытка очистки..."
    bash scripts/uninstall.sh 2>&1 | tee "$OUT/05_uninstall.log" || true
    exit "$install_rc"
fi

banner "ШАГ 2/5. setup_access.py: настройка ролей admin / app_user / guest (GRANT + SHOW GRANTS)"
docker compose exec -T client python scripts/setup_access.py 2>&1 | tee "$OUT/02_setup_access.log"
setup_rc=${PIPESTATUS[0]}

if [ "$setup_rc" -ne 0 ]; then
    echo "ОШИБКА: настройка политики не удалась (код $setup_rc), очистка..."
    bash scripts/uninstall.sh 2>&1 | tee "$OUT/05_uninstall.log" || true
    exit "$setup_rc"
fi

banner "ШАГ 3/5. check_policy.py: проверка корректности политики (матрица тестов)"
docker compose exec -T client python scripts/check_policy.py 2>&1 | tee "$OUT/03_check_policy.log"
policy_rc=${PIPESTATUS[0]}

banner "ШАГ 4/5. Демонстрация отрицательных кейсов (живые попытки запрещённых операций)"
{
    echo "Попытки запрещённых операций от имени guest и app_user (реальные ответы СУБД):"
    echo
    docker compose exec -T client python - <<'PYEOF'
import os
import mysql.connector

HOST = os.environ.get("DB_HOST", "mysql")
ATTEMPTS = [
    ("guest", os.environ.get("LAB8_GUEST_PASSWORD", "Guest8Pass"),
     "SELECT salary FROM company.employees"),
    ("guest", os.environ.get("LAB8_GUEST_PASSWORD", "Guest8Pass"),
     "SELECT passport_no FROM company.employees"),
    ("guest", os.environ.get("LAB8_GUEST_PASSWORD", "Guest8Pass"),
     "DELETE FROM company.employees"),
    ("app_user", os.environ.get("LAB8_USER_PASSWORD", "User8Pass"),
     "SELECT passport_no FROM company.employees"),
    ("app_user", os.environ.get("LAB8_USER_PASSWORD", "User8Pass"),
     "DELETE FROM company.employees"),
    ("app_user", os.environ.get("LAB8_USER_PASSWORD", "User8Pass"),
     "CREATE TABLE hack (id INT)"),
]
for user, pwd, sql in ATTEMPTS:
    print(f"{user}@company> {sql}")
    try:
        cnx = mysql.connector.connect(host=HOST, user=user, password=pwd,
                                      database="company", autocommit=False)
        cur = cnx.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        print(f"  ВЫПОЛНЕНО (НЕОЖИДАННО, нарушение политики!): {rows[:5]}")
        cnx.rollback()
    except mysql.connector.Error as e:
        print(f"  ОТКЛОНЕНО СУБД: ERROR {e.errno} ({e.sqlstate}): {e.msg}")
    print()
PYEOF
} 2>&1 | tee "$OUT/04_negative_cases.log"

banner "ШАГ 5/5. uninstall.sh: удаление СУБД и созданных ею объектов"
bash scripts/uninstall.sh 2>&1 | tee "$OUT/05_uninstall.log"
uninstall_rc=${PIPESTATUS[0]}

banner "ИТОГИ"
echo "install.sh      : $([ "$install_rc" -eq 0 ] && echo OK || echo "FAIL ($install_rc)")"
echo "setup_access.py : $([ "$setup_rc" -eq 0 ] && echo OK || echo "FAIL ($setup_rc)")"
echo "check_policy.py : $([ "$policy_rc" -eq 0 ] && echo OK || echo "FAIL ($policy_rc)")  (матрица политики: $([ "$policy_rc" -eq 0 ] && echo 'все проверки OK' || echo 'есть FAIL'))"
echo "uninstall.sh    : $([ "$uninstall_rc" -eq 0 ] && echo OK || echo "FAIL ($uninstall_rc)")"
echo "Вывод по шагам: $OUT/01..05_*.log"
[ "$policy_rc" -eq 0 ] && [ "$install_rc" -eq 0 ] && [ "$setup_rc" -eq 0 ] && [ "$uninstall_rc" -eq 0 ] || exit 1
exit 0
