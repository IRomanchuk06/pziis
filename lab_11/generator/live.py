#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Живой прогон: РЕАЛЬНЫЕ запросы к web и sshd «сегодняшнего дня».

В отличие от generator/backfill.py (синтетический backfill за прошлые дни),
здесь выполняются настоящие сетевые взаимодействия, и записи в журналы
пишут сами серверы (nginx и sshd), а не генератор:

  * реальные curl-запросы: обычный просмотр страниц + сканирование
    типичных уязвимых путей (/etc/passwd, /.env, /wp-admin, ...);
  * реальные SSH-попытки через sshpass: успешные входы (правильный пароль)
    и серия неудачных (перебор неверных паролей);
  * одна программная SSH-сессия через paramiko;
  * проба порта 22 без SSH-протокола (curl) — в auth.log попадает
    «Bad protocol version identification».

Внешний IP имитируется заголовком X-Forwarded-For (nginx пишет его в
кастомный формат журнала); реальный адрес источника в этот момент — IP
контейнера client в сети compose. Это честно указано в README и отчёте.
Полная расшифровка команд и результатов сохраняется в demo_output/live_run.txt.
"""

import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

WEB_HOST = os.environ.get("WEB_HOST", "web")
SSH_HOST = os.environ.get("SSH_HOST", "sshd")
SSH_USER = os.environ.get("SSH_USER", "labuser")
SSH_PASS = os.environ.get("SSH_PASS", "Lab11_Secret_Pass!")
TRANSCRIPT = Path(os.environ.get("LIVE_TRANSCRIPT",
                                 "/workspace/demo_output/live_run.txt"))

# «Внешние» IP для имитации X-Forwarded-For (RFC 5737, как в backfill).
OFFICE_IP = "192.0.2.10"      # обычный посетитель
ATTACKER_IP = "203.0.113.66"  # «атакующий» (сканирует веб)

UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
UA_CURL = "curl/8.5.0"

SCAN_PATHS = ["/etc/passwd", "/.env", "/wp-admin/", "/wp-login.php",
              "/phpmyadmin/", "/.git/config", "/shell.php", "/backup.zip",
              "/config.php", "/.aws/credentials", "/console/", "/admin"]

# Серия реальных неудачных SSH-попыток (перебор неверных паролей).
BRUTE_USERS = ["root", "root", "admin", "ubuntu", "labuser", "test",
               "root", "oracle", "admin", "postgres", "labuser", "root"]
BRUTE_PASSWORDS = ["123456", "password", "toor", "qwerty", "Passw0rd!",
                   "letmein", "admin123", "root123", "12345678", "abc123",
                   "labuser", "Welcome1"]

_t0 = time.time()
_out = None


def log(msg=""):
    global _out
    if _out is None:
        _out = TRANSCRIPT.open("w", encoding="utf-8")
    print(msg, flush=True)
    _out.write(msg + "\n")
    _out.flush()


def run(cmd, **kw):
    """Запуск процесса с выводом в транскрипт."""
    printable = " ".join(cmd)
    proc = subprocess.run(cmd, capture_output=True, text=True, **kw)
    tail = (proc.stdout.strip().splitlines() or [""])[-1:][0]
    errtail = (proc.stderr.strip().splitlines() or [""])[-1:][0]
    log(f"  $ {printable}")
    log(f"    -> exit={proc.returncode}"
        + (f' stdout="{tail[:120]}"' if tail else "")
        + (f' stderr="{errtail[:120]}"' if errtail else ""))
    return proc


def wait_web(timeout=60):
    """Ожидание готовности nginx (через requests)."""
    import requests
    url = f"http://{WEB_HOST}/"
    for attempt in range(timeout // 2):
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                log(f"[wait] {url} отвечает: HTTP {r.status_code} "
                    f"(попытка {attempt + 1})")
                return True
        except requests.RequestException as exc:
            log(f"[wait] {url} ещё не готов ({type(exc).__name__}), "
                f"попытка {attempt + 1}")
        time.sleep(2)
    return False


def wait_ssh(timeout=60):
    """Ожидание готовности sshd: читаем баннер протокола."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((SSH_HOST, 22), timeout=2) as s:
                banner = s.recv(64).decode(errors="replace").strip()
                if banner.startswith("SSH-"):
                    log(f"[wait] {SSH_HOST}:22 баннер: {banner}")
                    return True
        except OSError as exc:
            log(f"[wait] {SSH_HOST}:22 ещё не готов ({type(exc).__name__})")
        time.sleep(2)
    return False


def http_get(path, ua, xff, extra=()):
    return run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "5",
                "-A", ua, "-H", f"X-Forwarded-For: {xff}", *extra,
                f"http://{WEB_HOST}{path}"])


def main():
    TRANSCRIPT.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    log("=" * 72)
    log("ЖИВОЙ ПРОГОН (реальные запросы) — Лабораторная работа №11")
    log(f"Начало (UTC): {now:%Y-%m-%d %H:%M:%S}")
    log(f"Цели: http://{WEB_HOST}/ и {SSH_HOST}:22")
    log("Внешний IP имитируется заголовком X-Forwarded-For; записи в журналы")
    log("пишут сами nginx и sshd. Синтетический backfill прошлых дней —")
    log("в generator/backfill.py (см. README).")
    log("=" * 72)

    log("\n--- 0. Ожидание готовности сервисов ---")
    if not wait_web() or not wait_ssh():
        log("[ОШИБКА] сервисы не готовы, прерывание")
        sys.exit(1)

    log("\n--- 1. Демонстрация веб-сервера: тестовая страница ---")
    proc = run(["curl", "-sS", "--max-time", "5",
                f"http://{WEB_HOST}/"])
    head = [ln for ln in proc.stdout.splitlines() if ln.strip()][:6]
    for ln in head:
        log(f"  {ln.strip()}")

    log("\n--- 2. Обычный просмотр (реальные запросы посетителя) ---")
    http_get("/", UA_BROWSER, OFFICE_IP)
    http_get("/assets/style.css", UA_BROWSER, OFFICE_IP)
    http_get("/about.html", UA_BROWSER, OFFICE_IP)
    http_get("/old", UA_BROWSER, OFFICE_IP)
    http_get("/favicon.ico", UA_BROWSER, OFFICE_IP)

    log("\n--- 3. Сканирование уязвимостей (реальные запросы «атакующего») ---")
    log(f"    (UA curl, X-Forwarded-For: {ATTACKER_IP})")
    for path in SCAN_PATHS:
        http_get(path, UA_CURL, ATTACKER_IP)

    log("\n--- 4. Успешные входы по SSH (правильный пароль) ---")
    for i in range(2):
        run(["sshpass", "-p", SSH_PASS, "ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "PreferredAuthentications=password",
             "-o", "PubkeyAuthentication=no",
             "-o", "ConnectTimeout=5",
             f"{SSH_USER}@{SSH_HOST}",
             "uname -a && uptime" if i == 0 else "id && hostname"])

    log("\n--- 5. Программная SSH-сессия (paramiko) ---")
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(SSH_HOST, username=SSH_USER, password=SSH_PASS,
                       timeout=8, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = client.exec_command("uptime")
        log(f"  paramiko: uptime -> {stdout.read().decode().strip()}")
        client.close()
    except Exception as exc:  # noqa: BLE001 — фиксируем любую ошибку в транскрипт
        log(f"  paramiko: ошибка: {exc}")

    log("\n--- 6. Перебор паролей по SSH (реальные неудачные попытки, sshpass) ---")
    for user, pwd in zip(BRUTE_USERS, BRUTE_PASSWORDS):
        run(["sshpass", "-p", pwd, "ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "PreferredAuthentications=password",
             "-o", "PubkeyAuthentication=no",
             "-o", "ConnectTimeout=5",
             "-o", "NumberOfPasswordPrompts=1",
             f"{user}@{SSH_HOST}", "true"])
        time.sleep(0.3)

    log("\n--- 7. Проба порта 22 без SSH-протокола (curl) ---")
    run(["curl", "-sS", "--max-time", "2", f"http://{SSH_HOST}:22/"])

    log("\nЖивой прогон завершён. Журналы: runtime/logs/{access,error,auth}.log")
    _out.close()


if __name__ == "__main__":
    main()
