#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# Лабораторная работа 8. Программа №2 (setup_access.py)
# Настройка механизма контроля доступа в MySQL (выполняется внутри
# контейнера-клиента, подключается к СУБД по внутренней сети compose).
#
# Роли согласно методичке:
#   admin    - администратор системы: полный доступ ко всем подсистемам,
#              максимальные привилегии (ALL PRIVILEGES ON *.* WITH GRANT OPTION);
#   app_user - пользователь: полные/частичные права в подсистеме,
#              предоставленные администратором (SELECT/INSERT/UPDATE на
#              company.employees БЕЗ DELETE и без колонки passport_no через
#              column privileges; SELECT+INSERT на company.audit_log);
#   guest    - гость: права только на чтение отдельных фрагментов
#              (SELECT на представление company.v_public: id, name).
# =============================================================================
import os

import mysql.connector

HOST = os.environ.get("DB_HOST", "mysql")
ROOT_PASSWORD = os.environ.get("MYSQL_ROOT_PASSWORD", "lab8root")

# (роль, пароль) - лабовые значения, переопределяются через окружение
ROLES = [
    ("admin", os.environ.get("LAB8_ADMIN_PASSWORD", "Admin8Pass")),
    ("app_user", os.environ.get("LAB8_USER_PASSWORD", "User8Pass")),
    ("guest", os.environ.get("LAB8_GUEST_PASSWORD", "Guest8Pass")),
]

POLICY_DESCRIPTION = {
    "admin": ("полный доступ ко всем подсистемам: ALL PRIVILEGES ON *.* "
              "WITH GRANT OPTION"),
    "app_user": ("частичные права в подсистеме: SELECT(id,name,salary), "
                 "INSERT(id,name,salary), UPDATE(name,salary) на company.employees "
                 "(без DELETE, без колонки passport_no); SELECT+INSERT на "
                 "company.audit_log"),
    "guest": ("только чтение отдельных фрагментов: SELECT на представление "
              "company.v_public (id, name); salary и passport_no недоступны"),
}

# GRANT-скрипты для каждой роли
GRANTS = {
    "admin": [
        "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION",
    ],
    "app_user": [
        # column privileges: колонка passport_no не выдается вообще,
        # DELETE не выдается
        "GRANT SELECT (id, name, salary), INSERT (id, name, salary), "
        "UPDATE (name, salary) ON company.employees TO 'app_user'@'%'",
        "GRANT SELECT, INSERT ON company.audit_log TO 'app_user'@'%'",
    ],
    "guest": [
        # доступ только к представлению без чувствительных колонок
        "GRANT SELECT ON company.v_public TO 'guest'@'%'",
    ],
}


def run(cur, sql):
    print(f"  SQL> {sql}")
    cur.execute(sql)


def main():
    cnx = mysql.connector.connect(
        host=HOST, user="root", password=ROOT_PASSWORD, autocommit=True)
    cur = cnx.cursor()
    cur.execute("SELECT VERSION()")
    version = cur.fetchone()[0]
    print(f"[setup] Сервер БД: MySQL {version} (контейнер lab8-mysql)")
    print("[setup] Настройка механизма контроля доступа (3 роли)")

    print("\n[setup] 1/4. Представление v_public для гостя (id, name "
          "без salary/passport_no)")
    run(cur, "CREATE OR REPLACE VIEW company.v_public AS "
             "SELECT id, name FROM company.employees")

    print("\n[setup] 2/4. Создание учётных записей ролей")
    for user, pwd in ROLES:
        print(f"  -- роль {user}")
        run(cur, f"DROP USER IF EXISTS '{user}'@'%'")
        print(f"  SQL> CREATE USER '{user}'@'%' IDENTIFIED BY '***'")
        cur.execute(f"CREATE USER '{user}'@'%' IDENTIFIED BY %s", (pwd,))

    print("\n[setup] 3/4. Выдача привилегий (GRANT-скрипты)")
    for user, _ in ROLES:
        print(f"  -- роль {user}")
        for stmt in GRANTS[user]:
            run(cur, stmt)
    run(cur, "FLUSH PRIVILEGES")

    print("\n[setup] 4/4. SHOW GRANTS для каждой роли")
    for user, _ in ROLES:
        print(f"\n--- SHOW GRANTS FOR '{user}'@'%' ---")
        cur.execute(f"SHOW GRANTS FOR '{user}'@'%'")
        for (grant_stmt,) in cur.fetchall():
            print(f"  {grant_stmt};")

    print("\n[setup] Итоговая политика безопасности:")
    for user, _ in ROLES:
        print(f"  {user:<9}: {POLICY_DESCRIPTION[user]}")

    cur.close()
    cnx.close()
    print("\n[setup] Готово: механизм контроля доступа настроен.")


if __name__ == "__main__":
    main()
