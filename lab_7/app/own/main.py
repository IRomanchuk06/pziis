"""Интерактивное консольное приложение-хранилище (лабораторная работа 3).

Режимы (CLI): ``--mode safe`` (шифрование/хэширование/затирание) и
``--mode unsafe`` (plaintext в памяти). Командный протокол у режимов
одинаковый; каждая команда завершает вывод строкой ``[ok] ...`` либо
``[err] ...`` (это же позволяет внешнему драйверу демо синхронизироваться).

Секретные значения, введённые пользователем, никогда не выводятся в журнал
и не попадают в сообщения об ошибках; в транскрипте сессии они появляются
только при явной команде ``get`` (расшифровка по требованию пользователя).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

from vault import (
    KIND_PASSWORD,
    KIND_PUBLIC,
    KIND_SECRET,
    PBKDF2_ITERATIONS,
    SafeVault,
    UnsafeVault,
    ValidationError,
    make_vault,
    read_status_counters,
    validate_id,
    validate_kind,
)

PROMPT = "vault[{mode}]> "

HELP = f"""
Команды:
  help                          -- эта справка
  add secret <id>               -- добавить конфиденциальную запись (шифруется AES-256-GCM)
  add public <id>               -- добавить неконфиденциальную запись (хранится открыто)
  add password <id>             -- добавить пароль (PBKDF2-HMAC-SHA256, {PBKDF2_ITERATIONS} итераций)
  get <id>                      -- показать запись (секрет -- расшифровка на лету)
  verify <id>                   -- проверить пароль (только для type=password)
  update <id>                   -- заменить значение
  delete <id>                   -- удалить запись (safe: с затиранием памяти)
  list                          -- список записей
  stats                         -- RSS/CPU текущего процесса
  dumpcore <путь>               -- (демо) снять дамп памяти процесса через gdb gcore
  quit                          -- выход
"""


def read_line(prompt: str) -> str:
    """Чтение строки без упреждающего буферизации.

    ``input()`` использует буфер ``sys.stdin``, который читает поток с
    опережением и ДОЛГО хранит уже потреблённые байты -- введённые секреты
    оставались бы в его внутреннем буфере (реальный эффект виден в дампах,
    если читать через input()). Здесь читаем по одному байту через os.read:
    неизрасходованные данные остаются в буфере ядра (в адресное пространство
    процесса не попадают), а собственный bytearray-буфер затирается.
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    line_bytes = bytearray()
    while True:
        chunk = os.read(0, 1)
        if not chunk:  # EOF
            if line_bytes:
                break
            raise EOFError
        newline = chunk.find(b"\n")
        if newline >= 0:
            line_bytes += chunk[:newline]
            break
        line_bytes += chunk
    try:
        return line_bytes.decode("utf-8")
    finally:
        for i in range(len(line_bytes)):
            line_bytes[i] = 0
        line_bytes.clear()


def self_gcore(path: str) -> int:
    """Снимок собственной памяти процесса: gdb подключается к нашему PID."""
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    result = subprocess.run(
        ["gdb", "-p", str(os.getpid()), "-batch", "-ex", f"gcore {path}"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    with open(path + ".gdb.log", "w", encoding="utf-8") as fh:
        fh.write(result.stdout)
        fh.write(result.stderr)
    interesting = [
        line
        for line in result.stdout.splitlines()
        if line.strip() and "New" not in line and "Thread" not in line
    ]
    for line in interesting[-2:]:
        print(f"[dumpcore] {line}")
    print(f"[ok] dumpcore rc={result.returncode} path={path}")
    return result.returncode


def ask_value(prompt: str) -> str:
    try:
        return read_line(prompt)
    except EOFError:
        raise ValidationError("ввод значения прерван (EOF)") from None


def cmd_add(vault, args: list[str]) -> None:
    if len(args) != 2:
        raise ValidationError("формат: add <secret|public|password> <id>")
    kind, rid = args
    validate_kind(kind)      # валидация ДО запроса значения
    validate_id(rid)
    value = ask_value("Значение: ")
    vault.add(kind, rid, value)
    if vault.mode == "safe":
        # локальная ссылка на введённое значение больше не нужна
        del value
        vault.scrub()
    print(f"[ok] добавлена запись id={rid} type={kind}")


def cmd_get(vault, args: list[str]) -> None:
    if len(args) != 1:
        raise ValidationError("формат: get <id>")
    kind, value = vault.get(args[0])
    if kind == KIND_PASSWORD:
        print("[val] <значение неизвлекаемо: хранится только PBKDF2-хэш>")
        print("[ok] запись получена id=" + args[0])
        return
    print(f"[val] {value}")
    print(f"[ok] запись получена id={args[0]}")
    if vault.mode == "safe":
        del value
        vault.scrub()


def cmd_update(vault, args: list[str]) -> None:
    if len(args) != 1:
        raise ValidationError("формат: update <id>")
    vault.kind_of(args[0])  # проверка существования ДО запроса значения
    value = ask_value("Новое значение: ")
    vault.update(args[0], value)
    if vault.mode == "safe":
        del value
        vault.scrub()
    print(f"[ok] запись обновлена id={args[0]}")


def cmd_delete(vault, args: list[str]) -> None:
    if len(args) != 1:
        raise ValidationError("формат: delete <id>")
    vault.delete(args[0])
    print(f"[ok] запись удалена id={args[0]}")


def cmd_verify(vault, args: list[str]) -> None:
    if len(args) != 1:
        raise ValidationError("формат: verify <id>")
    if vault.kind_of(args[0]) != KIND_PASSWORD:
        raise ValidationError(f"запись {args[0]!r} не является паролем")
    candidate = ask_value("Проверочный пароль: ")
    ok = vault.verify_password(args[0], candidate)
    if vault.mode == "safe":
        del candidate
    print("[ok] проверка пароля id=" + args[0] + (" -> СОВПАДАЕТ" if ok else " -> не совпадает"))


def cmd_list(vault, args: list[str]) -> None:
    if args:
        raise ValidationError("формат: list")
    ids = vault.ids()
    for rid in ids:
        print(f"[rec] id={rid} type={vault.kind_of(rid)}")
    print(f"[ok] записей: {len(ids)}")


def cmd_stats(vault, args: list[str]) -> None:
    if args:
        raise ValidationError("формат: stats")
    counters = read_status_counters()
    print(
        "[stats] "
        + " ".join(f"{key}={value}" for key, value in counters.items())
        + f" records={len(vault.ids())}"
    )
    print("[ok] stats")


def cmd_help(vault, args: list[str]) -> None:
    for line in HELP.strip().splitlines():
        print(f"[h] {line}")
    print("[ok] help")


def cmd_noop(vault, args: list[str]) -> None:
    """Служебная пустая команда (синхронизация демо-драйвера)."""
    if args:
        raise ValidationError("формат: noop")
    print("[ok] noop")


COMMANDS = {
    "help": cmd_help,
    "noop": cmd_noop,
    "add": cmd_add,
    "get": cmd_get,
    "update": cmd_update,
    "delete": cmd_delete,
    "verify": cmd_verify,
    "list": cmd_list,
    "stats": cmd_stats,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Хранилище данных (ЛР3)")
    parser.add_argument("--mode", choices=("safe", "unsafe"), default="safe")
    ns = parser.parse_args()

    print(f"[banner] реализация=own (ЛР3 safe) режим={ns.mode} python={sys.version.split()[0]} pid={os.getpid()}")
    try:
        master_password = read_line("Мастер-пароль: ")
    except EOFError:
        print("[err] мастер-пароль не введён (EOF)")
        return 2

    try:
        vault = make_vault(ns.mode, master_password)
    except ValidationError as exc:
        print(f"[err] мастер-пароль отклонён: {exc}")
        return 2
    del master_password
    if isinstance(vault, SafeVault):
        vault.scrub()

    prompt = PROMPT.format(mode=ns.mode)
    while True:
        try:
            line = read_line(prompt)
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            print("[err] прервано пользователем (Ctrl+C); используйте quit")
            continue
        parts = line.strip().split()
        if not parts:
            continue
        command, args = parts[0].lower(), parts[1:]
        if command in ("quit", "exit"):
            break
        if command == "dumpcore":
            if len(args) != 1:
                print("[err] формат: dumpcore <путь>")
                continue
            try:
                self_gcore(args[0])
            except Exception as exc:  # noqa: BLE001 -- демо-команда, сообщаем кратко
                print(f"[err] dumpcore не выполнен: {type(exc).__name__}")
            continue
        handler = COMMANDS.get(command)
        if handler is None:
            print(f"[err] неизвестная команда {command!r} (help -- список команд)")
            continue
        try:
            handler(vault, args)
        except ValidationError as exc:
            print(f"[err] {exc}")
        except Exception as exc:  # noqa: BLE001 -- не роняем UI, не печатаем значение
            print(f"[err] внутренняя ошибка: {type(exc).__name__}")

    vault.close()
    if isinstance(vault, SafeVault):
        vault.scrub()
    print("[ok] выход; память, содержавшая секреты, затёрта" if isinstance(vault, SafeVault) else "[ok] выход")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
