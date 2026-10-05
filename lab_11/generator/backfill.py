#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
СИНТЕТИЧЕСКИЙ backfill журналов за предыдущие N=5 дней (честная пометка).

Записи, создаваемые этим скриптом, — синтетические. Они имитируют типичную
картину «интернет-трафика» за прошедшие дни (часы пик, фоновые ошибки,
сканеры уязвимостей, кампании брутфорса SSH), чтобы анализ можно было
выполнить «за несколько дней», не растягивая реальное время. Записи
последнего (шестого) дня формируются РЕАЛЬНЫМИ запросами generator/live.py
(curl + sshpass) и добавляются в те же файлы журналов.

IP-адреса синтетической части взяты из документационных диапазонов
RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) и намеренно не
указывают на реальные узлы. Воспроизводимость: фиксированный seed.

Форматы строк совпадают с реальными:
  access.log: remote - user [dd/Mon/YYYY:HH:MM:SS +0000] "REQ" status bytes
              "referer" "UA" xff="X-Forwarded-For"        (формат nginx «lab11»)
  error.log:  YYYY/MM/DD HH:MM:SS [level] pid#tid: *cid msg, client: IP, ...
  auth.log:   ISO-8601 hostname sshd[pid]: msg             (sshd -E)
"""

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# ---------------------------------------------------------------------------
# Параметры синтетического трафика
# ---------------------------------------------------------------------------

# Распределение веб-запросов по часам суток (0..23): ночной спад, пики
# около 10-12 и 19-21 часов.
WEB_HOURS = [2, 1, 1, 1, 1, 2, 3, 5, 8, 12, 14, 15, 10, 9, 11, 12, 10, 8, 9, 13, 15, 13, 8, 4]

# Фоновые SSH-подборы паролей чаще ночью.
AUTH_HOURS = [6, 5, 5, 4, 4, 3, 2, 2, 3, 4, 4, 4, 5, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 6]

# «Легитимные» IP посетителей (документационные диапазоны RFC 5737).
NORMAL_IPS = [
    ("192.0.2.10", 30), ("192.0.2.11", 8), ("192.0.2.27", 3),
    ("192.0.2.103", 2),
    ("198.51.100.7", 6), ("198.51.100.14", 5), ("198.51.100.55", 2),
    ("198.51.100.90", 2),
    ("203.0.113.5", 4), ("203.0.113.9", 3), ("203.0.113.42", 2),
    ("203.0.113.77", 1),
]

# Фальшивый «бот» (UA Googlebot с IP не из диапазонов Google).
FAKE_BOT_IP = "198.51.100.77"
FAKE_BOT_UA = ("Mozilla/5.0 (compatible; Googlebot/2.1; "
               "+http://www.google.com/bot.html)")

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "curl/8.5.0",
]

# (путь, вес, статус, базовый размер ответа)
NORMAL_PATHS = [
    ("/", 45, 200, 1150),
    ("/about.html", 12, 200, 950),
    ("/assets/style.css", 22, 200, 820),
    ("/old", 3, 301, 164),
    ("/assets/logo.png", 2, 404, 153),
    ("/team.html", 1, 404, 153),
    ("/blog/", 1, 404, 153),
]

REFERERS = ["-", "-", "-", "https://www.google.com/", "https://www.bing.com/",
            "http://web/", "https://example.com/links"]

# Пути, которыми прощупывают сервер сканеры уязвимостей.
SCAN_PATHS = [
    "/etc/passwd", "/.env", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
    "/.git/config", "/shell.php", "/backup.zip", "/config.php",
    "/.aws/credentials", "/cgi-bin/test.cgi", "/uploads/shell.php",
    "/actuator/health", "/console/", "/admin",
]

# Сканеры веб-сервера: IP -> сколько дней назад был всплеск сканирования.
WEB_SCANNERS = {"203.0.113.66": 4, "198.51.100.231": 2}

# SSH: фоновый шум подборов паролей.
SSH_NOISE_USERS = ["root", "admin", "test", "ubuntu", "oracle",
                   "postgres", "user", "pi", "deploy", "git"]
SSH_NOISE_IPS = ["192.0.2.140", "192.0.2.151", "192.0.2.168",
                 "198.51.100.120", "198.51.100.133", "198.51.100.201",
                 "203.0.113.150", "203.0.113.164", "203.0.113.201"]

# SSH: «пользовательский» IP, с которого ходят легитимные входы.
LEGIT_SSH_IP = "192.0.2.10"

# Кампании брутфорса: (IP, дней назад, целевой пользователь,
#                       число попыток, час начала, длительность в минутах)
BRUTE_CAMPAIGNS = [
    ("203.0.113.66", 3, "root", 45, 2, 150),    # ночной перебор root
    ("198.51.100.23", 1, "labuser", 30, 20, 75),  # вечерний перебор labuser
]

# У IP 198.51.100.23 перебор «завершается успехом» — один Accepted password
# с атакующего IP (типичный сюжет: слабый пароль подобран). Анализатор
# должен это пометить как инцидент.
BRUTE_SUCCESS_IP = "198.51.100.23"


# ---------------------------------------------------------------------------
# Формирование строк журналов
# ---------------------------------------------------------------------------

def access_line(dt, remote, path, status, size, referer, ua, xff):
    ts = f"{dt.day:02d}/{MONTHS[dt.month - 1]}/{dt.year}:{dt:%H:%M:%S} +0000"
    return (f'{remote} - - [{ts}] "GET {path} HTTP/1.1" {status} {size} '
            f'"{referer}" "{ua}" xff="{xff}"')


def error_line(dt, path, client_ip, rng):
    ts = dt.strftime("%Y/%m/%d %H:%M:%S")
    pid, tid = rng.randint(10, 40), rng.randint(10, 40)
    cid = rng.randint(10000, 999999)
    return (f'{ts} [error] {pid}#{tid}: *{cid} open() '
            f'"/usr/share/nginx/html{path}" failed (2: No such file or '
            f'directory), client: {client_ip}, server: _, '
            f'request: "GET {path} HTTP/1.1", host: "web"')


def auth_line(dt, pid, msg):
    ts = dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond:06d}+00:00"
    return f"{ts} lab11-sshd sshd[{pid}]: {msg}"


def rand_port(rng):
    return rng.randint(1024, 65534)


# ---------------------------------------------------------------------------
# Генерация событий дня
# ---------------------------------------------------------------------------

def gen_web_day(day, rng, events):
    """Обычный веб-трафик + всплески сканеров для одной календарной даты."""
    base = rng.randint(280, 380)
    for _ in range(base):
        hour = rng.choices(range(24), weights=WEB_HOURS)[0]
        dt = day.replace(hour=hour, minute=rng.randint(0, 59),
                         second=rng.randint(0, 59), microsecond=0)
        if rng.random() < 0.012:  # фальшивый «Googlebot»
            ip, ua = FAKE_BOT_IP, FAKE_BOT_UA
        else:
            ip = rng.choices([i for i, _ in NORMAL_IPS],
                             weights=[w for _, w in NORMAL_IPS])[0]
            ua = rng.choice(UAS)
        entry = rng.choices(NORMAL_PATHS,
                            weights=[p[1] for p in NORMAL_PATHS])[0]
        path, _, status, size = entry
        size = int(size * rng.uniform(0.85, 1.15))
        referer = rng.choice(REFERERS)
        events.append((dt, access_line(dt, ip, path, status, size, referer, ua, ip),
                       None if status != 404 else error_line(dt, path, ip, rng)))

    # Всплески сканирования уязвимостей.
    today = datetime.now(timezone.utc).date()
    for ip, days_ago in WEB_SCANNERS.items():
        if day.date() != today - timedelta(days=days_ago):
            continue
        start = day.replace(hour=rng.choice([3, 4, 13]), minute=rng.randint(0, 30),
                            second=0, microsecond=0)
        dt = start
        for path in rng.sample(SCAN_PATHS, k=rng.randint(12, 15)):
            dt = dt + timedelta(seconds=rng.randint(2, 45))
            status = 403 if path == "/admin" else 404
            ua = rng.choice(["curl/8.5.0", "python-requests/2.32.0",
                             "Mozilla/5.0 zgrab/0.x"])
            events.append((dt, access_line(dt, ip, path, status, 153 if status == 404 else 146,
                                           "-", ua, ip),
                           None if status == 403 else error_line(dt, path, ip, rng)))


def ssh_fail(events, dt, ip, user, rng, valid_users=("labuser", "root")):
    """Одна неудачная попытка входа (2-3 строки журнала, формат sshd -E)."""
    port = rand_port(rng)
    pid = rng.randint(100, 9999)
    if user not in valid_users:
        events.append((dt, auth_line(dt, pid,
                       f"Invalid user {user} from {ip} port {port}")))
        dt2 = dt + timedelta(milliseconds=rng.randint(100, 900))
        events.append((dt2, auth_line(dt2, pid,
                       f"Failed password for invalid user {user} from {ip} "
                       f"port {port} ssh2")))
    else:
        dt2 = dt + timedelta(milliseconds=rng.randint(100, 900))
        events.append((dt2, auth_line(dt2, pid,
                       f"Failed password for {user} from {ip} port {port} ssh2")))
    if rng.random() < 0.35:
        dt3 = dt2 + timedelta(milliseconds=rng.randint(200, 1500))
        if user in valid_users:
            msg = (f"Connection closed by authenticating user {user} "
                   f"{ip} port {port} [preauth]")
        else:
            msg = f"Connection closed by invalid user {user} {ip} port {port} [preauth]"
        events.append((dt3, auth_line(dt3, pid, msg)))
    return pid


def gen_auth_day(day, rng, events):
    today = datetime.now(timezone.utc).date()
    day_offset = (day.date() - today).days  # -5..-1

    # Легитимные входы «администратора» утром.
    for _ in range(rng.randint(1, 2)):
        dt = day.replace(hour=rng.randint(8, 11), minute=rng.randint(0, 59),
                         second=rng.randint(0, 59), microsecond=0)
        port = rand_port(rng)
        events.append((dt, auth_line(dt, rng.randint(100, 9999),
                       f"Accepted password for labuser from {LEGIT_SSH_IP} "
                       f"port {port} ssh2")))
        dt2 = dt + timedelta(seconds=rng.randint(20, 600))
        events.append((dt2, auth_line(dt2, rng.randint(100, 9999),
                       f"Disconnected from user labuser {LEGIT_SSH_IP} "
                       f"port {port}")))

    # Фоновый шум: 6-9 IP с 1-5 неудачными попытками каждый.
    for ip in rng.sample(SSH_NOISE_IPS, k=rng.randint(6, 9)):
        for _ in range(rng.randint(1, 5)):
            hour = rng.choices(range(24), weights=AUTH_HOURS)[0]
            dt = day.replace(hour=hour, minute=rng.randint(0, 59),
                             second=rng.randint(0, 59), microsecond=0)
            ssh_fail(events, dt, ip, rng.choice(SSH_NOISE_USERS), rng)

    # «Did not receive identification string» — сканирование порта без SSH-баннера.
    if rng.random() < 0.5:
        dt = day.replace(hour=rng.randint(1, 23), minute=rng.randint(0, 59),
                         second=rng.randint(0, 59), microsecond=0)
        ip = rng.choice(SSH_NOISE_IPS)
        events.append((dt, auth_line(dt, rng.randint(100, 9999),
                       f"Did not receive identification string from {ip} "
                       f"port {rand_port(rng)}")))

    # Кампании брутфорса.
    for ip, days_ago, user, count, start_hour, span_min in BRUTE_CAMPAIGNS:
        if day.date() != today - timedelta(days=days_ago):
            continue
        dt = day.replace(hour=start_hour, minute=rng.randint(0, 59),
                         second=rng.randint(0, 59), microsecond=0)
        for _ in range(count):
            dt = dt + timedelta(seconds=rng.uniform(1.0, span_min * 60 / count))
            ssh_fail(events, dt, ip, user, rng)
        if ip == BRUTE_SUCCESS_IP:
            # Перебор «завершился успехом» — подбор пароля labuser.
            dt_ok = dt + timedelta(seconds=rng.randint(2, 6))
            port = rand_port(rng)
            events.append((dt_ok, auth_line(dt_ok, rng.randint(100, 9999),
                           f"Accepted password for {user} from {ip} "
                           f"port {port} ssh2")))
            dt_disc = dt_ok + timedelta(seconds=rng.randint(30, 300))
            events.append((dt_disc, auth_line(dt_disc, rng.randint(100, 9999),
                           f"Disconnected from user {user} {ip} port {port}")))


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Синтетический backfill журналов web/sshd за N предыдущих дней")
    parser.add_argument("--days", type=int, default=5,
                        help="сколько прошлых дней сгенерировать (по умолчанию 5)")
    parser.add_argument("--out", default="/workspace/runtime/logs",
                        help="каталог с журналами")
    parser.add_argument("--seed", type=int, default=11011,
                        help="seed генератора (воспроизводимость)")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    now = datetime.now(timezone.utc)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    events = []  # (datetime, строка access/error/auth, имя файла)
    for d in range(args.days, 0, -1):
        day = (now - timedelta(days=d)).replace(hour=0, minute=0, second=0,
                                                microsecond=0)
        web, auth = [], []
        gen_web_day(day, rng, web)
        gen_auth_day(day, rng, auth)
        for dt, acc, err in web:
            events.append((dt, acc, "access.log"))
            if err:
                events.append((dt, err, "error.log"))
        for dt, line in auth:
            events.append((dt, line, "auth.log"))

    events.sort(key=lambda e: e[0])

    handles = {name: open(out / name, "a", encoding="utf-8")
               for name in ("access.log", "error.log", "auth.log")}
    counts = {name: 0 for name in handles}
    for _, line, name in events:
        handles[name].write(line + "\n")
        counts[name] += 1
    for fh in handles.values():
        fh.close()

    end = max(e[0] for e in events)
    print(f"[backfill] СИНТЕТИЧЕСКИЕ записи за {args.days} дней "
          f"(по {end:%Y-%m-%d} включительно, UTC):")
    for name in ("access.log", "error.log", "auth.log"):
        print(f"[backfill]   {name}: +{counts[name]} строк -> {out / name}")
    print("[backfill] Реальные события сегодняшнего дня добавит generator/live.py")


if __name__ == "__main__":
    main()
