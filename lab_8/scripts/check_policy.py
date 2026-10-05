#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# Лабораторная работа 8. Программа №3 (check_policy.py)
# Проверка корректности работы настроенной политики безопасности MySQL.
#
# Матрица тестов: от имени каждой роли (admin, app_user, guest) выполняются
# попытки SELECT / INSERT / UPDATE / DELETE / DDL / чтение запрещённых колонок
# / GRANT. Ожидание по политике сравнивается с фактическим результатом.
# Если хотя бы один тест FAIL - программа завершается с кодом != 0.
#
# Каждый успешный DML откатывается (rollback), DDL и GRANT-пробы убираются
# cleanup-командами, поэтому проверка не изменяет данные.
# =============================================================================
import os
import sys

import mysql.connector

HOST = os.environ.get("DB_HOST", "mysql")
DB = "company"

ROLE_PASSWORDS = {
    "admin": os.environ.get("LAB8_ADMIN_PASSWORD", "Admin8Pass"),
    "app_user": os.environ.get("LAB8_USER_PASSWORD", "User8Pass"),
    "guest": os.environ.get("LAB8_GUEST_PASSWORD", "Guest8Pass"),
}

# Коды ошибок MySQL, означающие "доступ запрещён политикой":
# 1044/1045 - access denied (DB/account), 1142 - table command denied,
# 1143 - column command denied, 1144 - illegal GRANT/REVOKE,
# 1227 - privilege check failed, 1410 - not allowed to create user w/ GRANT
DENY_ERRNOS = {1044, 1045, 1142, 1143, 1144, 1227, 1410}

# (роль, операция, SQL, ожидание по политике allow|deny, cleanup SQL)
CASES = [
    # --------------------------- admin: всё разрешено ----------------------
    ("admin", "SELECT employees (id, name, salary)",
     "SELECT id, name, salary FROM employees", "allow", None),
    ("admin", "SELECT employees.passport_no (запрещённая для др. колонка)",
     "SELECT passport_no FROM employees", "allow", None),
    ("admin", "SELECT v_public (id, name)",
     "SELECT id, name FROM v_public", "allow", None),
    ("admin", "SELECT audit_log",
     "SELECT db_user, action FROM audit_log", "allow", None),
    ("admin", "INSERT INTO employees (вкл. passport_no)",
     "INSERT INTO employees (name, salary, passport_no) "
     "VALUES ('Probe Admin', 111.11, 'ZZ0000001')", "allow", None),
    ("admin", "UPDATE employees SET salary",
     "UPDATE employees SET salary = salary + 1 WHERE id = 1", "allow", None),
    ("admin", "DELETE FROM employees",
     "DELETE FROM employees WHERE id = 1", "allow", None),
    ("admin", "DDL: CREATE TABLE",
     "CREATE TABLE tmp_probe_admin (id INT)", "allow",
     "DROP TABLE tmp_probe_admin"),
    ("admin", "GRANT SELECT TO guest (есть GRANT OPTION)",
     "GRANT SELECT ON company.audit_log TO 'guest'@'%'", "allow",
     "REVOKE SELECT ON company.audit_log FROM 'guest'@'%'"),
    # ------------------- app_user: частичные права -------------------------
    ("app_user", "SELECT employees (id, name, salary)",
     "SELECT id, name, salary FROM employees", "allow", None),
    ("app_user", "SELECT employees.passport_no (запрещённая колонка)",
     "SELECT passport_no FROM employees", "deny", None),
    ("app_user", "SELECT v_public (не выдано)",
     "SELECT id, name FROM v_public", "deny", None),
    ("app_user", "SELECT audit_log",
     "SELECT db_user, action FROM audit_log", "allow", None),
    ("app_user", "INSERT INTO employees (name, salary)",
     "INSERT INTO employees (name, salary) VALUES ('Probe User', 222.22)",
     "allow", None),
    ("app_user", "INSERT INTO employees (вкл. passport_no - запрещена)",
     "INSERT INTO employees (name, salary, passport_no) "
     "VALUES ('Probe User', 222.22, 'ZZ0000002')", "deny", None),
    ("app_user", "UPDATE employees SET salary",
     "UPDATE employees SET salary = salary + 1 WHERE id = 1", "allow", None),
    ("app_user", "UPDATE employees SET passport_no (запрещена)",
     "UPDATE employees SET passport_no = 'ZZ9999999' WHERE id = 1",
     "deny", None),
    ("app_user", "DELETE FROM employees (DELETE не выдан)",
     "DELETE FROM employees WHERE id = 1", "deny", None),
    ("app_user", "INSERT INTO audit_log",
     "INSERT INTO audit_log (db_user, action) VALUES (CURRENT_USER(), 'probe')",
     "allow", None),
    ("app_user", "DDL: CREATE TABLE",
     "CREATE TABLE tmp_probe_user (id INT)", "deny", None),
    ("app_user", "GRANT SELECT TO guest (нет GRANT OPTION)",
     "GRANT SELECT ON company.v_public TO 'guest'@'%'", "deny", None),
    # --------------- guest: только чтение v_public -------------------------
    ("guest", "SELECT v_public (id, name)",
     "SELECT id, name FROM v_public", "allow", None),
    ("guest", "SELECT employees (id, name) - таблица не выдана",
     "SELECT id, name FROM employees", "deny", None),
    ("guest", "SELECT employees.salary",
     "SELECT salary FROM employees", "deny", None),
    ("guest", "SELECT employees.passport_no",
     "SELECT passport_no FROM employees", "deny", None),
    ("guest", "SELECT audit_log",
     "SELECT db_user, action FROM audit_log", "deny", None),
    ("guest", "INSERT INTO employees",
     "INSERT INTO employees (name, salary) VALUES ('Probe Guest', 0.00)",
     "deny", None),
    ("guest", "UPDATE employees",
     "UPDATE employees SET salary = 0 WHERE id = 1", "deny", None),
    ("guest", "DELETE FROM employees",
     "DELETE FROM employees WHERE id = 1", "deny", None),
    ("guest", "DDL: CREATE TABLE",
     "CREATE TABLE tmp_probe_guest (id INT)", "deny", None),
    ("guest", "GRANT SELECT TO app_user",
     "GRANT SELECT ON company.v_public TO 'app_user'@'%'", "deny", None),
]


def main():
    print("=" * 104)
    print("ПРОВЕРКА КОРРЕКТНОСТИ ПОЛИТИКИ БЕЗОПАСНОСТИ MySQL (лаб. работа 8)")
    print("=" * 104)
    print(f"Сервер: {HOST}:3306 (внутренняя сеть compose), БД: {DB}")
    print("Роли: admin (ALL PRIVILEGES + GRANT OPTION), "
          "app_user (частичные права), guest (только v_public)")

    # Подключение от имени каждой роли
    conns = {}
    for role, pwd in ROLE_PASSWORDS.items():
        try:
            conns[role] = mysql.connector.connect(
                host=HOST, port=3306, database=DB,
                user=role, password=pwd, autocommit=False)
            print(f"Подключение {role}@{HOST}: OK")
        except mysql.connector.Error as e:
            print(f"Подключение {role}@{HOST}: ОШИБКА ({e})")
            return 2
    print()

    results = []  # (num, role, op, expected, actual, ok, err)
    for num, (role, op, sql, expected, cleanup) in enumerate(CASES, 1):
        conn = conns[role]
        err = None
        try:
            cur = conn.cursor()
            cur.execute(sql)
            cur.fetchall()
            if cleanup:
                cur.execute(cleanup)
            cur.close()
            actual = "allow"
        except mysql.connector.Error as e:
            err = e
            actual = "deny" if e.errno in DENY_ERRNOS else "error"
        finally:
            try:
                conn.rollback()  # успешные DML не должны менять данные
            except mysql.connector.Error:
                pass
        ok = (actual == expected)
        results.append((num, role, op, expected, actual, ok, err, sql))

    # Таблица результатов
    hdr = (f"{'№':>3}  {'Роль':<9}{'Операция':<52}{'Ожид.':<8}{'Факт':<8}{'Итог':<6}")
    print(hdr)
    print("-" * len(hdr))
    for num, role, op, expected, actual, ok, _err, _sql in results:
        verdict = "OK" if ok else "FAIL"
        op_disp = op if len(op) <= 51 else op[:48] + "..."
        print(f"{num:>3}  {role:<9}{op_disp:<52}{expected:<8}{actual:<8}{verdict:<6}")

    ok_count = sum(1 for r in results if r[5])
    fail_count = len(results) - ok_count

    # Детализация отрицательных кейсов (ожидаемо запрещённых)
    print("\nОтрицательные кейсы (ожидание = deny), фактические ошибки MySQL:")
    for num, role, op, expected, actual, ok, err, sql in results:
        if expected == "deny":
            if err is not None:
                print(f"  [{num}] {role}: {sql}")
                print(f"        -> отклонено: MySQL error {err.errno}: {err.msg}")
            else:
                print(f"  [{num}] {role}: {sql}")
                print("        -> ВНИМАНИЕ: команда выполнилась, хотя должна быть запрещена!")

    # Детализация ошибок/расхождений
    problems = [r for r in results if not r[5]]
    if problems:
        print("\nРАСХОЖДЕНИЯ С ПОЛИТИКОЙ (FAIL):")
        for num, role, op, expected, actual, _ok, err, sql in problems:
            print(f"  [{num}] {role}: {op} -> ожидалось {expected}, фактически {actual}")
            if err is not None:
                print(f"        ({err})")

    print("\n" + "=" * 104)
    print(f"ИТОГО: проверок {len(results)}, OK {ok_count}, FAIL {fail_count}")
    print("ВЕРДИКТ: политика безопасности " +
          ("КОРРЕКТНА (все проверки пройдены)" if fail_count == 0 else "НАРУШЕНА"))
    print("=" * 104)

    for conn in conns.values():
        conn.close()
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
