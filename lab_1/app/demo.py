"""Демонстрационный сценарий: все операции приложения по порядку.

Запускается в контейнере (CMD образа); вывод сохраняется run.sh в demo_output/.
"""
import os
import time

from service import AccessDenied, App, AuthError, NotFound, ValidationError

DATA_DIR = "/srv/data"
ALICE_PASSWORD = "Demo-Alice-2026-Key"
BOB_PASSWORD = "Demo-Bob-2026-Key"
EVE_PASSWORD = "Demo-Eve-2026-Key"


def header(text: str) -> None:
    print(f"\n=== {text} ===")


def ok(text: str) -> None:
    print(f"  [OK]     {text}")


def denied(text: str) -> None:
    print(f"  [ОТКАЗ]  {text}")


def info(text: str) -> None:
    print(f"  [i]      {text}")


def expect_denied(label: str, fn) -> None:
    """Выполняет операцию, ожидая управляемый отказ."""
    try:
        fn()
    except (AccessDenied, AuthError, ValidationError, NotFound) as exc:
        denied(f"{label} -> {type(exc).__name__}: {exc}")
        return
    ok(f"{label} -> операция НЕ отклонена (не ожидалось!)")


def short(token: str) -> str:
    return token[:8] + "…"


def main() -> None:
    master = os.environ.get("MASTER_PASSWORD", "")
    admin_password = os.environ.get("ADMIN_PASSWORD", "")

    print("#" * 70)
    print("# Лабораторная работа 1. Оценка защищённости разработанного приложения")
    print("# Демонстрация: аутентификация, роли, данные, сессии, аудит")
    print("#" * 70)
    info("мастер-пароль AES получен из env MASTER_PASSWORD (в лог не выводится)")
    info("пароль bootstrap-admin получен из env ADMIN_PASSWORD (в лог не выводится)")

    header("Шаг 1. Инициализация системы")
    app = App(DATA_DIR, master, admin_password=admin_password)
    ok("хранилище /srv/data создано (каталог 0700, файлы 0600)")
    ok("соль KDF сгенерирована (kdf.salt), ключ AES-256 выведен из мастер-пароля")
    ok("bootstrap-пользователь 'admin' (роль admin) создан")

    header("Шаг 2. Аутентификация")
    expect_denied("авторизация admin с НЕВЕРНЫМ паролем",
                  lambda: app.login("admin", "totally-wrong-password"))
    admin_token = app.login("admin", admin_password)
    ok(f"авторизация admin прошла, сессия выдана (токен {short(admin_token)}, TTL 1800 c)")

    header("Шаг 3. Управление пользователями (admin)")
    expect_denied("создание пользователя с коротким паролем 'q1'",
                  lambda: app.add_user(admin_token, "alice", "q1", "user"))
    app.add_user(admin_token, "alice", ALICE_PASSWORD, "user")
    ok("создан пользователь 'alice' (роль user)")
    app.add_user(admin_token, "bob", BOB_PASSWORD, "guest")
    ok("создан пользователь 'bob' (роль guest)")
    expect_denied("создание пользователя с недопустимой ролью 'root'",
                  lambda: app.add_user(admin_token, "eve", EVE_PASSWORD, "root"))

    header("Шаг 4. Конфиденциальные данные (admin)")
    secret = app.add_record(admin_token, "Ключи сервисного аккаунта",
                            "SERVICE-TOKEN: demo-secret-token-42", True)
    ok(f"создана конфиденциальная запись id={secret['id']} (шифруется AES-GCM)")

    header("Шаг 5. Пользователь alice: свои и чужие данные")
    alice_token = app.login("alice", ALICE_PASSWORD)
    ok(f"авторизация alice (токен {short(alice_token)})")
    note = app.add_record(alice_token, "Регламент резервного копирования",
                          "Бэкап выполняется по расписанию cron: 03:00 ежедневно", False)
    ok(f"создана неконфиденциальная запись id={note['id']}")
    api_key = app.add_record(alice_token, "Личный API-ключ",
                             "sk-live-DEMO-KEY-9876-5432", True)
    ok(f"создана конфиденциальная запись alice id={api_key['id']}")
    app.edit_record(alice_token, api_key["id"], content="sk-live-DEMO-KEY-1111-2222 (ротация)")
    ok("alice изменила свою конфиденциальную запись (перешифрована)")
    expect_denied("alice читает ЧУЖУЮ конфиденциальную запись admin",
                  lambda: app.get_record(alice_token, secret["id"]))
    found = app.search_records(alice_token, "регламент")
    ok(f"поиск 'регламент': найдено {len(found)} (неконфиденциальные доступны)")
    found = app.search_records(alice_token, "ключ")
    ok(f"поиск 'ключ' у alice: найдено {len(found)} (только СВОИ конфиденциальные)")
    expect_denied("alice пытается добавить пользователя",
                  lambda: app.add_user(alice_token, "eve", EVE_PASSWORD, "user"))
    scratch = app.add_record(alice_token, "Черновик", "временная запись", False)
    app.delete_record(alice_token, scratch["id"])
    ok(f"alice создала и удалила свою запись id={scratch['id']}")

    header("Шаг 6. Тайм-аут сессии")
    ttl_token = app.sessions.create("alice", ttl=2).token
    info(f"выдана сессия alice с укороченным TTL=2 c (токен {short(ttl_token)})")
    time.sleep(3)
    expect_denied("операция по истёкшей сессии",
                  lambda: app.get_record(ttl_token, api_key["id"]))

    header("Шаг 7. Деавторизация")
    app.logout(alice_token)
    ok("alice выполнила logout, сессия закрыта")
    expect_denied("повторное использование токена после logout",
                  lambda: app.get_record(alice_token, api_key["id"]))

    header("Шаг 8. Гость bob: только чтение неконфиденциальных")
    bob_token = app.login("bob", BOB_PASSWORD)
    ok(f"авторизация bob (токен {short(bob_token)})")
    found = app.search_records(bob_token, "")
    ok(f"просмотр всех доступных записей: {len(found)} (только неконфиденциальные)")
    for rec in found:
        info(f"видит: id={rec['id']} «{rec['title']}»")
    expect_denied("bob пытается создать запись",
                  lambda: app.add_record(bob_token, "Заметка", "текст", False))
    expect_denied("bob читает конфиденциальную запись admin",
                  lambda: app.get_record(bob_token, secret["id"]))
    found = app.search_records(bob_token, "ключ")
    ok(f"поиск 'ключ' у гостя: найдено {len(found)} (конфиденциальные скрыты)")

    header("Шаг 9. Admin: полный доступ")
    admin_token = app.login("admin", admin_password)
    rec = app.get_record(admin_token, api_key["id"])
    ok(f"admin прочитал конфиденциальную запись alice: «{rec['title']}» (расшифрована)")
    app.edit_record(admin_token, note["id"], content="Бэкап 03:00; проверен администратором")
    ok("admin отредактировал запись пользователя")
    app.delete_user(admin_token, "bob")
    ok("admin удалил пользователя 'bob'")
    expect_denied("операция под сессией удалённого пользователя bob",
                  lambda: app.search_records(bob_token, ""))
    app.logout(admin_token)
    ok("admin завершил сессию")

    header("Шаг 10. Состояние хранилища и журнал аудита")
    print("  --- data/records.json (как лежит на диске; конфиденциальные — шифротекст) ---")
    with open(os.path.join(DATA_DIR, "records.json"), encoding="utf-8") as fh:
        for line in fh.read().splitlines():
            print("    " + line)
    print("  --- data/audit.log (последние 12 записей) ---")
    for line in app.audit.tail(12):
        print("    " + line)
    print("  --- права доступа к файлам данных ---")
    for name in sorted(os.listdir(DATA_DIR)):
        mode = os.stat(os.path.join(DATA_DIR, name)).st_mode & 0o777
        print(f"    {name}: {oct(mode)}")

    print("\nДемонстрация завершена.")


if __name__ == "__main__":
    main()
