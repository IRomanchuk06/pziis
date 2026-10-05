"""Интерактивная консоль приложения (отдельно от демо-сценария).

Запуск: docker compose run --rm -T app python cli.py
"""
import getpass
import os

from service import AccessDenied, App, AuthError, NotFound, ValidationError


def print_records(found: list) -> None:
    if not found:
        print("  (пусто)")
    for rec in found:
        mark = "[C]" if rec["confidential"] else "[ ]"
        print(f"  {mark} {rec['id']}  {rec['owner']:<10}  {rec['title']}")


def records_menu(app: App, token: str) -> None:
    while True:
        print("Записи: 1-список/поиск  2-создать  3-прочитать  4-изменить  5-удалить  0-выход")
        cmd = input("> ").strip()
        try:
            if cmd == "1":
                query = input("подстрока (Enter — все): ")
                print_records(app.search_records(token, query))
            elif cmd == "2":
                confidential = input("конфиденциальная? (y/N): ").lower() == "y"
                title = input("заголовок: ")
                content = input("содержимое: ")
                rec = app.add_record(token, title, content, confidential)
                print(f"  создана запись id={rec['id']}")
            elif cmd == "3":
                print(app.get_record(token, input("id записи: ")))
            elif cmd == "4":
                rec_id = input("id записи: ")
                title = input("новый заголовок (Enter — не менять): ") or None
                content = input("новое содержимое (Enter — не менять): ") or None
                app.edit_record(token, rec_id, title, content)
                print("  запись обновлена")
            elif cmd == "5":
                app.delete_record(token, input("id записи: "))
                print("  запись удалена")
            elif cmd == "0":
                return
        except (AccessDenied, AuthError, ValidationError, NotFound) as exc:
            print(f"  отказ: {exc}")


def admin_menu(app: App, token: str) -> None:
    while True:
        print("Администрирование: 1-добавить пользователя  2-удалить пользователя  0-далее")
        cmd = input("> ").strip()
        try:
            if cmd == "1":
                login = input("логин: ")
                password = getpass.getpass("пароль: ")
                role = input("роль (admin/user/guest): ")
                app.add_user(token, login, password, role)
                print(f"  пользователь {login} создан")
            elif cmd == "2":
                app.delete_user(token, input("логин: "))
                print("  пользователь удалён")
            elif cmd == "0":
                return
        except (AccessDenied, AuthError, ValidationError, NotFound) as exc:
            print(f"  отказ: {exc}")


def main() -> None:
    data_dir = os.environ.get("DATA_DIR", "/srv/data")
    master = os.environ.get("MASTER_PASSWORD") or getpass.getpass("Мастер-пароль: ")
    app = App(data_dir, master, admin_password=os.environ.get("ADMIN_PASSWORD"))
    print("Консоль приложения. 'exit' в поле логина — выход.")
    while True:
        login = input("\nЛогин: ").strip()
        if login == "exit":
            return
        password = getpass.getpass("Пароль: ")
        try:
            token = app.login(login, password)
        except AuthError as exc:
            print(f"  отказ: {exc}")
            continue
        role = app.users[login]["role"]
        print(f"  сессия открыта, роль: {role}")
        while True:
            if role == "admin":
                admin_menu(app, token)
                print("1-работа с записями  2-выйти (logout)")
                if input("> ").strip() == "2":
                    app.logout(token)
                    print("  сессия закрыта")
                    break
            else:
                records_menu(app, token)
                app.logout(token)
                print("  сессия закрыта")
                break


if __name__ == "__main__":
    main()
