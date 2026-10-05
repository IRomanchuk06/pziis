#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Анализатор результатов лабораторной работы №12 (IDS Suricata).

Сравнивает фазу ДО (IDS отключена) и фазу ПОСЛЕ (Suricata включена):

  * demo_output/before/  - nginx access.log, auth.log, лог генератора;
  * demo_output/after/   - то же + fast.log, eve.json, suricata.log.

Результат печатается в stdout и сохраняется в demo_output/before_after.txt.
"""
import json
import os
import re
import sys
from collections import Counter

BASE = os.environ.get("DEMO_DIR", "/demo_output")
BEFORE = os.path.join(BASE, "before")
AFTER = os.path.join(BASE, "after")
OUT_FILE = os.path.join(BASE, "before_after.txt")

ATTACKER_IP = "172.28.100.20"

# Категоризация HTTP-запросов по URI (согласована с traffic_gen.py)
PATTERNS = [
    ("path traversal (/etc/passwd)", re.compile(r"(\.\./|%2e%2e|\.\.%2f|%2e\.%2e)", re.I)),
    ("SQL-инъекция в query string",
     re.compile(r"(union(?:%20|\+|%2b)+(?:all(?:%20|\+|%2b)+)?select"
                r"|(?:%27|')?(?:%20|\+)*(?:or|and)(?:%20|\+)+(?:%27|')?1(?:%27|')?"
                r"(?:%20|\+)*(?:=|%3d)|%27--|%20--|--)", re.I)),
    ("сканирование путей",
     re.compile(r"(\.(?:env|git|bak|sql|zip|old)(?:\?|/|$)"
                r"|wp-login|phpmyadmin|/admin(?:$|/)|server-status|actuator|cgi-bin)", re.I)),
]

FAST_LOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.*?)\s+\[\*\*\]\s+\[Classification:\s*(?P<cls>.*?)\]\s+"
    r"\[Priority:\s*(?P<prio>\d+)\]\s+"
    r"\{(?P<proto>\w+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)")


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return []


def parse_nginx(lines):
    """access.log -> (все, атаки по категориям, коды ответов)."""
    total = 0
    attacks = Counter()
    codes = Counter()
    req_re = re.compile(r'"(\S+)\s+(\S+)\s+HTTP/[^"]*"\s+(\d{3})')
    for line in lines:
        m = req_re.search(line)
        if not m:
            continue
        total += 1
        codes[m.group(3)] += 1
        uri = m.group(2)
        for name, pat in PATTERNS:
            if pat.search(uri):
                attacks[name] += 1
                break
    return total, attacks, codes


def parse_generator(lines):
    """Лог генератора -> счётчики по категориям."""
    c = Counter()
    for line in lines:
        if line.startswith("SUMMARY|"):
            _, cat, n = line.split("|")
            if cat != "total":
                c[cat] = int(n)
    return c


def parse_auth(lines):
    # одна неудачная попытка = строка "Failed password ..."
    failed = sum(1 for l in lines if "Failed password" in l)
    accepted = sum(1 for l in lines if "Accepted password" in l)
    return failed, accepted


def parse_fast(lines):
    """fast.log -> список алертов."""
    alerts = []
    for line in lines:
        m = FAST_LOG_RE.match(line)
        if m:
            alerts.append(m.groupdict())
    return alerts


def parse_eve(lines):
    """eve.json -> события alert."""
    alerts = []
    for line in lines:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") == "alert":
            alerts.append(ev)
    return alerts


def fmt(n):
    return str(n)


def main():
    out = []
    say = out.append
    say("=" * 74)
    say("ЛАБОРАТОРНАЯ РАБОТА №12. IDS Suricata. СВОДКА ДО/ПОСЛЕ")
    say("=" * 74)

    # ------------------------------ ДО ------------------------------
    b_gen = parse_generator(read(os.path.join(BEFORE, "attacker_traffic.log")))
    b_nginx = parse_nginx(read(os.path.join(BEFORE, "nginx_access.log")))
    b_auth = parse_auth(read(os.path.join(BEFORE, "auth.log")))
    b_fast = parse_fast(read(os.path.join(BEFORE, "fast.log")))

    # ------------------------------ ПОСЛЕ ---------------------------
    a_gen = parse_generator(read(os.path.join(AFTER, "attacker_traffic.log")))
    a_nginx = parse_nginx(read(os.path.join(AFTER, "nginx_access.log")))
    a_auth = parse_auth(read(os.path.join(AFTER, "auth.log")))
    a_fast = parse_fast(read(os.path.join(AFTER, "fast.log")))
    a_eve = parse_eve(read(os.path.join(AFTER, "eve.json")))

    say("")
    say("1) ФАЗА «ДО» (IDS отключена): трафик прошёл, следы - только в сырых логах")
    say("-" * 74)
    say("   Сгенерировано трафика:         HTTP-запросов: %s (норм. %s, атак. HTTP %s), "
        "nmap-скан: %s, попыток SSH: %s" % (
            fmt(b_nginx[0]),
            fmt(b_gen.get("normal", 0)),
            fmt(b_gen.get("traversal", 0) + b_gen.get("sqli", 0) + b_gen.get("scan-http", 0)),
            fmt(b_gen.get("scan-port", 0)),
            fmt(b_gen.get("ssh-brute", 0))))
    say("   nginx access.log:              записей: %s; по категориям: %s; коды ответов: %s" % (
        fmt(b_nginx[0]),
        dict(b_nginx[1]) if b_nginx[1] else "{}",
        dict(sorted(b_nginx[2].items()))))
    say("   auth.log (sshd):               неудачных попыток входа: %s" % fmt(b_auth[0]))
    say("   АЛЕРТОВ IDS:                   %s  (система обнаружения вторжений не работала -"
        " атаки не классифицированы и не заблокированы)" % fmt(len(b_fast)))

    say("")
    say("2) ФАЗА «ПОСЛЕ» (Suricata включена, тот же генератор трафика)")
    say("-" * 74)
    say("   Сгенерировано трафика:         HTTP-запросов: %s (норм. %s, атак. HTTP %s), "
        "nmap-скан: %s, попыток SSH: %s" % (
            fmt(a_nginx[0]),
            fmt(a_gen.get("normal", 0)),
            fmt(a_gen.get("traversal", 0) + a_gen.get("sqli", 0) + a_gen.get("scan-http", 0)),
            fmt(a_gen.get("scan-port", 0)),
            fmt(a_gen.get("ssh-brute", 0))))
    say("   nginx access.log:              записей: %s (IDS работает в режиме обнаружения -"
        " запросы доходят, но классифицируются)" % fmt(a_nginx[0]))
    say("   auth.log (sshd):               неудачных попыток входа: %s" % fmt(a_auth[0]))

    if a_fast:
        sid_msg = {}
        per_sid = Counter()
        per_cls = Counter()
        srcs = Counter()
        for al in a_fast:
            key = (al["sid"], al["msg"])
            sid_msg[key] = sid_msg.get(key, 0) + 1
            per_sid[al["sid"]] += 1
            per_cls[al["cls"]] += 1
            if al["src"].split(":")[0] == ATTACKER_IP:
                srcs[ATTACKER_IP] += 1
        say("   АЛЕРТОВ IDS (fast.log):        %s" % fmt(len(a_fast)))
        say("")
        say("   Разбивка алертов по правилам (signature id -> число срабатываний):")
        say("   %-12s %-55s %s" % ("SID", "ПРАВИЛО", "АЛЕРТОВ"))
        for (sid, msg), cnt in sorted(sid_msg.items(), key=lambda kv: -kv[1]):
            say("   %-12s %-55s %s" % (sid, msg[:55], cnt))
        say("")
        say("   По классификации (Classification):")
        for cls, cnt in per_cls.most_common():
            say("     %-58s %s" % (cls, cnt))
        say("")
        say("   Топ источников атак (src -> число алертов):")
        for ip, cnt in srcs.most_common(5):
            say("     %-58s %s" % (ip, cnt))
    else:
        say("   АЛЕРТОВ IDS (fast.log):        0  !! ПРОВЕРКА НЕ ПРОЙДЕНА")

    # сверка с eve.json (структурированные события)
    say("")
    say("3) Сверка по eve.json (структурированный журнал событий)")
    say("-" * 74)
    say("   Событий типа alert в eve.json: %s" % fmt(len(a_eve)))
    if a_eve:
        cats = Counter(ev["alert"].get("category", "?") for ev in a_eve)
        sevs = Counter(ev["alert"].get("severity") for ev in a_eve)
        say("   По категориям GTI/classification: %s" % dict(cats.most_common()))
        say("   По severity (1 - высокий ... 3 - низкий): %s" % dict(sorted(sevs.items())))
        http_ev = [ev for ev in a_eve if ev.get("event_type") == "alert" and ev.get("http")]
        if http_ev:
            say("   Примеры атакующих HTTP-запросов из eve.json (hostname + url):")
            seen = set()
            for ev in http_ev:
                u = ev["http"].get("hostname", "") + ev["http"].get("url", "")
                if u in seen:
                    continue
                seen.add(u)
                say("     %s %s -> %s (sid %s)" % (
                    ev["timestamp"][11:19], ev["src_ip"], u[:60],
                    ev["alert"].get("signature_id")))
                if len(seen) >= 6:
                    break

    say("")
    say("4) ИТОГ")
    say("-" * 74)
    attacks_before_http = sum(b_nginx[1].values())
    attacks_after_http = sum(a_nginx[1].values())
    say("   ДО:   атакующих действий всего: %s (HTTP-атак: %s, неудачных входов SSH: %s)." % (
        fmt(attacks_before_http + b_auth[0]), fmt(attacks_before_http), fmt(b_auth[0])))
    say("         Они зафиксированы ТОЛЬКО пост-фактум в сырых логах nginx/sshd;")
    say("         алертов и автоматической классификации нет (%s)." % fmt(len(b_fast)))
    say("   ПОСЛЕ: тот же профиль трафика (HTTP-атак: %s, входов SSH: %s) породил" % (
        fmt(attacks_after_http), fmt(a_auth[0])))
    say("         %s алертов Suricata в fast.log и %s событий alert в eve.json." % (
        fmt(len(a_fast)), fmt(len(a_eve))))
    say("   Прирост наблюдаемости: %s -> %s классифицированных событий безопасности." % (
        fmt(len(b_fast)), fmt(len(a_fast))))
    say("")

    text = "\n".join(out)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(text)
    return 0 if a_fast else 1


if __name__ == "__main__":
    sys.exit(main())
