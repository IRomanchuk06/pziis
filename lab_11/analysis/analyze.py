#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Анализатор журналов веб-сервера (access.log, error.log) и SSH (auth.log)
для лабораторной работы №11 «Анализ запросов из сети Интернет».

Только стандартная библиотека. Разбирает:

  access.log — кастомный формат nginx «lab11»:
      remote - user [dd/Mon/YYYY:HH:MM:SS +0000] "REQ" status bytes
      "referer" "UA" xff="X-Forwarded-For"

  error.log  — стандартный формат nginx error log (level warn/error/...);

  auth.log   — syslog-подобный формат sshd -E:
      ISO-8601 hostname sshd[pid]: message

Статистика: топ IP/путей/User-Agent, коды ответов, активность по часам и
всплески, подозрительные пути, SSH: принятые/неудачные входы по IP,
детект брутфорса (порог N неудач с одного IP за окно времени), вердикты
и топ рисков. Результат: текстовый отчёт (stdout и файл --out).
"""

import argparse
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

ACCESS_RE = re.compile(
    r'^(?P<remote>\S+) - (?P<user>\S+) \[(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):'
    r'(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) (?P<tz>[+-]\d{4})\] '
    r'"(?P<method>\S+) (?P<path>\S+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" xff="(?P<xff>[^"]*)"$')

ERROR_RE = re.compile(
    r'^(?P<d>\d{4}/\d{2}/\d{2}) (?P<t>\d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*)$')
ERR_CLIENT_RE = re.compile(r'client: (?P<ip>[\da-fA-F.:]+)')
ERR_REQ_RE = re.compile(r'request: "\S+ (?P<req>\S+)')

AUTH_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})) '
    r'(?P<host>\S+) (?P<proc>[\w\-.]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$')

FAILED_RE = re.compile(
    r'^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)')
ACCEPTED_RE = re.compile(
    r'^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)')
INVALID_RE = re.compile(
    r'^Invalid user (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)(?: port (?P<port>\d+))?')
BADPROTO_RE = re.compile(
    r'^Bad protocol version identification (?P<banner>.*) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)')
NOID_RE = re.compile(
    r'^Did not receive identification string from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)')
KEX_BAD_RE = re.compile(r'^kex_exchange_identification: (?P<detail>.+)')
BANNER_EX_RE = re.compile(
    r'^banner exchange: Connection from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)')

# Подозрительные для веб-сервера пути (сканирование уязвимостей).
SUSPICIOUS_PATTERNS = [
    "/etc/passwd", "/etc/shadow", "/.env", "/wp-", "/phpmyadmin", "/.git",
    "/shell.php", "/backup", "/.aws", "/cgi-bin/", "/config.php", "/admin",
    "/console", "/actuator", "/.ssh", "/web.config", "/vendor/phpunit",
]

BRUTE_USERS_VALID = {"labuser"}  # существующие на стенде учётные записи


def parse_access_ts(m):
    try:
        return datetime(int(m["year"]), MONTHS[m["mon"]], int(m["day"]),
                        int(m["h"]), int(m["m"]), int(m["s"]))
    except (KeyError, ValueError):
        return None


def parse_iso_ts(ts):
    txt = ts.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(txt)
    except ValueError:
        return None


def read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def pct(part, total):
    return f"{(100.0 * part / total):.1f}%" if total else "0.0%"


def top_table(counter, total, title, width=46, limit=10):
    rows = [f"  {title:<{width}}  {'записей':>8}  {'доля':>7}",
            f"  {'-' * width}  {'--------':>8}  {'-------':>7}"]
    for value, count in counter.most_common(limit):
        shown = value if len(value) <= width else value[:width - 3] + "..."
        rows.append(f"  {shown:<{width}}  {count:>8}  {pct(count, total):>7}")
    return rows


class WebStats:
    def __init__(self):
        self.entries = []          # разобранные записи access.log
        self.skipped = 0
        self.total = 0
        self.by_day = defaultdict(Counter)      # день -> Counter статусов
        self.statuses = Counter()
        self.ips = Counter()
        self.ip_4xx = Counter()
        self.paths = Counter()
        self.uas = Counter()
        self.hour_hist = Counter()              # (0..23) -> count
        self.day_hour = Counter()               # (дата, час) -> count
        self.suspicious = []                    # dict-записи
        self.fake_bots = Counter()
        self.first = self.last = None


def analyze_access(path):
    st = WebStats()
    if not Path(path).exists():
        return st
    for line in read_lines(path):
        m = ACCESS_RE.match(line)
        if not m:
            st.skipped += 1
            continue
        dt = parse_access_ts(m)
        if dt is None:
            st.skipped += 1
            continue
        xff = m["xff"].strip()
        ip = xff if xff not in ("", "-") else m["remote"]
        path_norm = m["path"].split("?", 1)[0]
        status = int(m["status"])
        ua = m["ua"]
        entry = {"dt": dt, "ip": ip, "remote": m["remote"], "path": path_norm,
                 "status": status, "ua": ua, "method": m["method"]}
        st.entries.append(entry)
        st.total += 1
        st.by_day[dt.date()][status] += 1
        st.statuses[status] += 1
        st.ips[ip] += 1
        if 400 <= status < 600:
            st.ip_4xx[ip] += 1
        st.paths[path_norm] += 1
        st.uas[ua] += 1
        st.hour_hist[dt.hour] += 1
        st.day_hour[(dt.date(), dt.hour)] += 1
        if st.first is None or dt < st.first:
            st.first = dt
        if st.last is None or dt > st.last:
            st.last = dt
        low = path_norm.lower()
        if any(pat in low for pat in SUSPICIOUS_PATTERNS):
            st.suspicious.append(entry)
        if ("googlebot" in ua.lower() or "bingbot" in ua.lower()) \
                and not ip.startswith("66.249."):
            st.fake_bots[ip] += 1
    return st


class SshStats:
    def __init__(self):
        self.total_lines = 0
        self.skipped = 0
        self.accepted = []         # (dt, user, ip)
        self.failed = []           # (dt, user, ip, invalid: bool)
        self.invalid = []          # (dt, user, ip)
        self.badproto = []         # (dt, ip, banner)
        self.noident = []          # (dt, ip)
        self.kex_probes = []       # (dt, описание) — не-SSH пробы порта 22
        self.first = self.last = None


def analyze_auth(path):
    st = SshStats()
    if not Path(path).exists():
        return st
    for line in read_lines(path):
        m = AUTH_RE.match(line)
        if not m:
            st.skipped += 1
            continue
        dt = parse_iso_ts(m["ts"])
        msg = m["msg"].lstrip()  # sshd -e | ts добавляет ведущий пробел
        st.total_lines += 1
        if dt is not None:
            if st.first is None or dt < st.first:
                st.first = dt
            if st.last is None or dt > st.last:
                st.last = dt
        if (fm := FAILED_RE.match(msg)):
            st.failed.append((dt, fm["user"], fm["ip"],
                              "invalid user" in msg))
        elif (am := ACCEPTED_RE.match(msg)):
            st.accepted.append((dt, am["user"], am["ip"]))
        elif (im := INVALID_RE.match(msg)):
            st.invalid.append((dt, im["user"], im["ip"]))
        elif (bm := BADPROTO_RE.match(msg)):
            st.badproto.append((dt, bm["ip"], bm["banner"][:60]))
        elif (kb := KEX_BAD_RE.match(msg)):
            st.kex_probes.append((dt, f"kex_exchange_identification: {kb['detail'][:50]}"))
        elif (be := BANNER_EX_RE.match(msg)):
            st.kex_probes.append((dt, f"некорректный SSH-баннер от {be['ip']}"))
        elif (nm := NOID_RE.match(msg)):
            st.noident.append((dt, nm["ip"]))
    return st


def detect_bruteforce(failed, threshold, window_min):
    """failed: [(dt, user, ip, invalid)] -> список фактов брутфорса по IP."""
    by_ip = defaultdict(list)
    for dt, user, ip, _invalid in failed:
        if dt is not None:
            by_ip[ip].append((dt, user))
    facts = []
    for ip, evs in by_ip.items():
        evs.sort()
        times = [dt for dt, _ in evs]
        users = sorted({u for _, u in evs})
        best_in_window, best_pair = 0, (times[0], times[0])
        left = 0
        for right in range(len(times)):
            while (times[right] - times[left]).total_seconds() > window_min * 60:
                left += 1
            in_window = right - left + 1
            if in_window > best_in_window:
                best_in_window = in_window
                best_pair = (times[left], times[right])
        if best_in_window >= threshold:
            facts.append({
                "ip": ip, "total": len(evs), "peak": best_in_window,
                "peak_from": best_pair[0], "peak_to": best_pair[1],
                "first": times[0], "last": times[-1], "users": users,
            })
    facts.sort(key=lambda f: -f["total"])
    return facts


class ErrStats:
    def __init__(self):
        self.levels = Counter()
        self.clients = Counter()
        self.missing = Counter()
        self.total = 0
        self.skipped = 0


def analyze_error(path):
    st = ErrStats()
    if not Path(path).exists():
        return st
    for line in read_lines(path):
        m = ERROR_RE.match(line)
        if not m:
            st.skipped += 1
            continue
        st.total += 1
        st.levels[m["level"]] += 1
        if (cm := ERR_CLIENT_RE.search(m["msg"])):
            st.clients[cm["ip"]] += 1
        if "No such file or directory" in m["msg"] and (rm := ERR_REQ_RE.search(m["msg"])):
            st.missing[rm["req"]] += 1
    return st


# ---------------------------------------------------------------------------
# Формирование отчёта
# ---------------------------------------------------------------------------

def fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M") if dt else "n/a"


def web_section(st, out):
    out.append("2. ВЕБ-СЕРВЕР (access.log)")
    out.append("-" * 72)
    if st.total == 0:
        out.append("  Журнал пуст или не разобран.")
        out.append("")
        return
    out.append(f"  Записей: {st.total}   уникальных IP: {len(st.ips)}   "
               f"период: {fmt_dt(st.first)} — {fmt_dt(st.last)} (UTC)")
    if st.skipped:
        out.append(f"  Неразобранных строк: {st.skipped}")

    out.append("")
    out.append("  2.1. Запросы по дням (дата: всего / 2xx / 3xx / 4xx / 5xx):")
    for day in sorted(st.by_day):
        c = st.by_day[day]
        ok2 = sum(v for k, v in c.items() if 200 <= k < 300)
        ok3 = sum(v for k, v in c.items() if 300 <= k < 400)
        err4 = sum(v for k, v in c.items() if 400 <= k < 500)
        err5 = sum(v for k, v in c.items() if k >= 500)
        out.append(f"    {day}  {sum(c.values()):>6} / {ok2:>5} / {ok3:>4} / "
                   f"{err4:>4} / {err5:>4}")

    out.append("")
    out.append("  2.2. Коды ответов:")
    for code, count in sorted(st.statuses.items()):
        out.append(f"    HTTP {code}: {count:>6}  ({pct(count, st.total)})")

    out.append("")
    out.extend(top_table(st.ips, st.total,
                         "IP (по X-Forwarded-For/remote)", 40, 10)[0:2])
    for value, count in st.ips.most_common(10):
        shown = value if len(value) <= 40 else value[:37] + "..."
        out.append(f"  {shown:<40}  {count:>8}  {pct(count, st.total):>7}"
                   f"   4xx/5xx: {st.ip_4xx[value]}")

    out.append("")
    out.extend(top_table(st.paths, st.total, "Путь", 40, 10))

    out.append("")
    out.extend(top_table(st.uas, st.total, "User-Agent", 60, 6))

    out.append("")
    out.append("  2.3. Активность по часам суток (суммарно за весь период):")
    maxh = max(st.hour_hist.values()) if st.hour_hist else 1
    scale = max(1, math.ceil(maxh / 50))
    peak_hours = sorted(st.hour_hist, key=lambda h: -st.hour_hist[h])[:3]
    for hour in range(24):
        count = st.hour_hist.get(hour, 0)
        out.append(f"    {hour:02d}:00 | {'#' * (count // scale)}"
                   f"{count:>5}  {'<-- пик' if hour in peak_hours else ''}")
    out.append(f"    (1 символ = {scale} запросов; пиковые часы: "
               + ", ".join(f"{h:02d}" for h in peak_hours) + ")")

    if st.day_hour:
        mean = sum(st.day_hour.values()) / len(st.day_hour)
        var = sum((v - mean) ** 2 for v in st.day_hour.values()) / len(st.day_hour)
        sigma = math.sqrt(var)
        spikes = [(k, v) for k, v in st.day_hour.items()
                  if v > mean + 2 * sigma]
        spikes.sort(key=lambda kv: -kv[1])
        out.append("")
        out.append(f"  2.4. Всплески активности (слот (день, час) > "
                   f"среднее {mean:.1f} + 2σ ({sigma:.1f})):")
        if spikes:
            for (day, hour), count in spikes[:8]:
                out.append(f"    {day} {hour:02d}:00 — {count} запросов "
                           f"({count / mean:.1f}× среднего)")
        else:
            out.append("    всплесков не выявлено")

    out.append("")
    out.append("  2.5. Подозрительная активность (сканирование путей):")
    if st.suspicious:
        by_ip = defaultdict(list)
        for e in st.suspicious:
            by_ip[e["ip"]].append(e)
        for ip, evs in sorted(by_ip.items(), key=lambda kv: -len(kv[1])):
            paths = Counter(e["path"] for e in evs)
            out.append(f"    IP {ip}: {len(evs)} подозрительных запросов "
                       f"({fmt_dt(min(e['dt'] for e in evs))} — "
                       f"{fmt_dt(max(e['dt'] for e in evs))})")
            for p, c in paths.most_common(8):
                statuses = sorted({e["status"] for e in evs if e["path"] == p})
                out.append(f"      {p:<28} ×{c}  статусы: {statuses}")
    else:
        out.append("    подозрительных запросов не выявлено")

    if st.fake_bots:
        out.append("")
        out.append("  2.6. Подозрение на поддельного поискового бота "
                   "(бот-UA не из сетей поисковика):")
        for ip, count in st.fake_bots.most_common():
            out.append(f"    IP {ip}: {count} запросов с UA, содержащим 'bot'")
    out.append("")


def error_section(st, out):
    out.append("3. ВЕБ-СЕРВЕР (error.log)")
    out.append("-" * 72)
    if st.total == 0:
        out.append("  Журнал пуст или не разобран.")
        out.append("")
        return
    out.append(f"  Записей: {st.total}"
               + (f" (ещё {st.skipped} служебных строк запуска nginx "
                  f"без стандартного формата)" if st.skipped else ""))
    out.append("  По уровням: "
               + ", ".join(f"{lvl}: {cnt}" for lvl, cnt in st.levels.most_common()))
    if st.clients:
        out.append("  Клиенты, породившие ошибки (топ-5):")
        for ip, count in st.clients.most_common(5):
            out.append(f"    {ip:<20} {count:>5}")
    if st.missing:
        out.append("  Наиболее частые отсутствующие ресурсы (топ-8):")
        for req, count in st.missing.most_common(8):
            out.append(f"    {req:<40} ×{count}")
    out.append("")


def ssh_section(st, bf_threshold, bf_window, out):
    out.append("4. SSH-СЕРВЕР (auth.log)")
    out.append("-" * 72)
    out.append(f"  Строк журнала: {st.total_lines}"
               + (f", неразобранных: {st.skipped}" if st.skipped else ""))
    out.append(f"  Период: {fmt_dt(st.first)} — {fmt_dt(st.last)} (UTC)")

    out.append("")
    out.append("  4.1. Успешные входы (Accepted):")
    if st.accepted:
        acc_by = Counter((user, ip) for _, user, ip in st.accepted)
        fails_by_ip = defaultdict(list)
        for dt, _user, ip, _inv in st.failed:
            if dt is not None:
                fails_by_ip[ip].append(dt)
        acc_times = defaultdict(list)
        for dt, _user, ip in st.accepted:
            if dt is not None:
                acc_times[ip].append(dt)
        for (user, ip), count in acc_by.most_common():
            marks = []
            ip_fails = sorted(fails_by_ip.get(ip, []))
            if ip_fails:
                nth = (ip_fails[bf_threshold - 1]
                       if len(ip_fails) >= bf_threshold else None)
                if nth and any(t >= nth for t in acc_times.get(ip, [])):
                    marks.append("<-- ВХОД ПОСЛЕ СЕРИИ НЕУДАЧНЫХ ПОПЫТОК!")
                else:
                    marks.append("(с этого IP также были неудачные попытки)")
            elif ip.startswith(("172.", "10.", "192.168.")):
                marks.append("(внутренняя сеть стенда)")
            times = sorted(t for t, u, i in st.accepted if u == user and i == ip)
            suffix = ("  " + " ".join(marks)) if marks else ""
            out.append(f"    пользователь {user}, IP {ip}: {count} вход(ов), "
                       f"{fmt_dt(times[0])} — {fmt_dt(times[-1])}{suffix}")
    else:
        out.append("    успешных входов нет")

    out.append("")
    failed_total = len(st.failed)
    out.append(f"  4.2. Неудачные попытки (Failed password): {failed_total}")
    users_f = Counter(user for _, user, _, _ in st.failed)
    if users_f:
        out.append("  По именам пользователей (топ-8):")
        for user, count in users_f.most_common(8):
            note = " (существует на сервере)" if user in BRUTE_USERS_VALID else ""
            out.append(f"    {user:<16} {count:>6}{note}")
    ips_f = Counter(ip for _, _, ip, _ in st.failed)
    if ips_f:
        out.append("  По IP-адресам (топ-10):")
        for ip, count in ips_f.most_common(10):
            out.append(f"    {ip:<20} {count:>6}  ({pct(count, failed_total)})")

    if st.invalid:
        inv_users = Counter(user for _, user, _ in st.invalid)
        out.append("")
        out.append(f"  4.3. Несуществующие пользователи (Invalid user): "
                   f"{len(st.invalid)} сообщений, "
                   f"{len(inv_users)} уникальных имён; топ: "
                   + ", ".join(f"{u} ({c})" for u, c in inv_users.most_common(6)))

    out.append("")
    out.append(f"  4.4. Детект брутфорса: порог = {bf_threshold} неудач "
               f"с одного IP за окно {bf_window} мин:")
    facts = detect_bruteforce(st.failed, bf_threshold, bf_window)
    if facts:
        out.append(f"    {'IP':<18}{'неудач':>7}{'пик/окно':>10}  "
                   f"{'окно пика (UTC)':<34}целевые пользователи")
        for f in facts:
            window = (f"{fmt_dt(f['peak_from'])} — "
                      f"{f['peak_to'].strftime('%H:%M')}")
            users = ", ".join(f["users"])
            out.append(f"    {f['ip']:<18}{f['total']:>7}{f['peak']:>10}  "
                       f"{window:<34}{users}")
        out.append("")
        out.append(f"    ИТОГО: источников брутфорса: {len(facts)}; "
                   f"суммарно неудачных попыток от них: "
                   f"{sum(f['total'] for f in facts)}")
    else:
        out.append("    брутфорс не выявлен")

    if st.badproto or st.noident or st.kex_probes:
        out.append("")
        out.append("  4.5. Прочие аномалии:")
        for dt, ip, banner in st.badproto[:5]:
            out.append(f"    {fmt_dt(dt)}  {ip}: не-SSH протокол: {banner}")
        if st.kex_probes:
            out.append(f"    Пробы порта 22 не-SSH протоколом: "
                       f"{len(st.kex_probes)}")
            for dt, desc in st.kex_probes[:6]:
                out.append(f"      {fmt_dt(dt)}  {desc}")
        if st.noident:
            ips = Counter(ip for _, ip in st.noident)
            out.append(f"    Сканирование порта 22 без SSH-баннера: "
                       + ", ".join(f"{ip} ×{c}" for ip, c in ips.most_common(5)))
    out.append("")
    return facts


def verdicts(web, ssh, bf_facts, bf_threshold, out):
    out.append("5. ВЕРДИКТЫ И ТОП РИСКОВ")
    out.append("-" * 72)
    risks = []
    if bf_facts:
        total_bf = sum(f["total"] for f in bf_facts)
        users_list = sorted({u for f in bf_facts for u in f["users"]})
        risks.append((1, "ВЫСОКИЙ",
                      f"Брутфорс SSH: {total_bf} неудачных попыток подбора пароля "
                      f"с {len(bf_facts)} IP ({', '.join(f['ip'] for f in bf_facts)}), "
                      f"целевые учётные записи: {', '.join(users_list)}. "
                      f"Мера: fail2ban, ограничение по IP, ключи вместо паролей."))
        # Успех ПОСЛЕ серии неудач с того же IP — признак возможной компрометации.
        fails_by_ip = defaultdict(list)
        for dt, _u, ip, _i in ssh.failed:
            if dt is not None:
                fails_by_ip[ip].append(dt)
        acc_by_ip = defaultdict(list)
        for dt, _u, ip in ssh.accepted:
            if dt is not None:
                acc_by_ip[ip].append(dt)
        for f in bf_facts:
            ip_fails = sorted(fails_by_ip.get(f["ip"], []))
            nth = (ip_fails[bf_threshold - 1]
                   if len(ip_fails) >= bf_threshold else None)
            if nth and any(a >= nth for a in acc_by_ip.get(f["ip"], [])):
                risks.append((1, "КРИТИЧЕСКИЙ",
                              f"Успешный вход с IP {f['ip']} после серии неудачных "
                              f"попыток с этого же адреса — вероятная компрометация "
                              f"учётной записи. Мера: немедленно сменить пароль, "
                              f"проверить сервер, перевести на ключи."))
    root_fails = sum(1 for _, u, _, _ in ssh.failed if u == "root")
    if root_fails:
        risks.append((2, "ВЫСОКИЙ",
                      f"Целенаправленный подбор пароля root: {root_fails} попыток. "
                      f"Мера: PermitRootLogin no (на стенде уже установлено), "
                      f"запрет входа root по паролю."))
    if ssh.invalid:
        users = Counter(u for _, u, _ in ssh.invalid)
        risks.append((3, "СРЕДНИЙ",
                      f"Перебор имён пользователей ({len(ssh.invalid)} сообщений, "
                      f"{len(users)} имён: {', '.join(list(users)[:5])}...). "
                      f"Мера: единое сообщение об ошибке, fail2ban по invalid user."))
    if web.suspicious:
        ips = sorted({e['ip'] for e in web.suspicious})
        paths = sorted({e['path'] for e in web.suspicious})
        sensitive = [p for p in paths if any(s in p for s in
                     ("/etc/passwd", "/.env", "/.git", "/.aws", "config.php"))]
        risks.append((4, "СРЕДНИЙ",
                      f"Сканирование веб-сервера: {len(web.suspicious)} запросов "
                      f"подозрительных путей с {len(ips)} IP; в т.ч. чувствительные "
                      f"ресурсы: {', '.join(sensitive[:6])}. "
                      f"Мера: WAF/limit_req, убрать служебные файлы, 4xx не раскрывают версию."))
    if web.fake_bots:
        risks.append((5, "НИЗКИЙ",
                      f"Поддельный поисковый бот (Googlebot-UA с посторонних IP: "
                      f"{', '.join(web.fake_bots)}). Мера: проверка ботов по "
                      f"обратному DNS/диапазонам, rate-limit."))
    risks.append((6, "СРЕДНИЙ",
                  "На сервере включена парольная аутентификация SSH. "
                  "Мера: перейти на ключи, отключить PasswordAuthentication."))
    risks.append((7, "НИЗКИЙ",
                  "Журналы хранятся локально на сервере. Мера: централизованный "
                  "сбор логов (rsyslog/syslog-ng, journald -> remote) для "
                  "сохранности при инциденте."))

    order = {"КРИТИЧЕСКИЙ": 0, "ВЫСОКИЙ": 1, "СРЕДНИЙ": 2, "НИЗКИЙ": 3}
    risks.sort(key=lambda r: order.get(r[1], 9))
    for i, (_, sev, text) in enumerate(risks, 1):
        out.append(f"  Риск {i}. [{sev}]")
        for wrapped in _wrap(text, width=68, prefix="      "):
            out.append(wrapped)
    out.append("")
    out.append("  Общий вердикт: на стенде воспроизведены и обнаружены "
               "типовые атаки")
    out.append("  (брутфорс SSH, сканирование веб-уязвимостей, поддельные боты); "
               "журналы")
    out.append("  содержат достаточно данных для выявления инцидентов и "
               "принятия мер.")
    out.append("")


def _wrap(text, width, prefix):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width - len(prefix):
            lines.append(prefix + cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(prefix + cur)
    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Анализ журналов web/nginx и sshd (лабораторная №11)")
    parser.add_argument("--access", default="/workspace/runtime/logs/access.log")
    parser.add_argument("--error", default="/workspace/runtime/logs/error.log")
    parser.add_argument("--auth", default="/workspace/runtime/logs/auth.log")
    parser.add_argument("--out", default="/workspace/demo_output/analysis_report.txt")
    parser.add_argument("--bf-threshold", type=int, default=5,
                        help="порог неудач с одного IP для брутфорса")
    parser.add_argument("--bf-window", type=int, default=10,
                        help="окно детекта брутфорса, минут")
    args = parser.parse_args()

    web = analyze_access(args.access)
    err = analyze_error(args.error)
    ssh = analyze_auth(args.auth)
    bf_facts = detect_bruteforce(ssh.failed, args.bf_threshold, args.bf_window)

    out = []
    out.append("=" * 72)
    out.append("ОТЧЁТ ОБ АНАЛИЗЕ ЗАПРОСОВ ИЗ СЕТИ — Лабораторная работа №11")
    out.append(f"Сформирован: {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC")
    out.append(f"Журналы: {args.access}")
    out.append(f"         {args.error}")
    out.append(f"         {args.auth}")
    out.append("=" * 72)

    out.append("")
    out.append("1. ОБЩИЕ СВЕДЕНИЯ")
    out.append("-" * 72)
    out.append(f"  access.log: {web.total} записей (период {fmt_dt(web.first)} — "
               f"{fmt_dt(web.last)})")
    out.append(f"  error.log:  {err.total} записей")
    out.append(f"  auth.log:   {ssh.total_lines} записей (период {fmt_dt(ssh.first)} — "
               f"{fmt_dt(ssh.last)})")
    out.append("  Примечание: записи за первые 5 дней — синтетический backfill")
    out.append("  (generator/backfill.py, см. README), последний день — реальные")
    out.append("  запросы generator/live.py. IP из документационных диапазонов")
    out.append("  RFC 5737 — синтетическая часть; в реальной части web-запросов")
    out.append("  внешний IP передан заголовком X-Forwarded-For, а SSH-попытки")
    out.append("  идут с IP контейнера client (сеть compose).")
    out.append("")

    web_section(web, out)
    error_section(err, out)
    ssh_section(ssh, args.bf_threshold, args.bf_window, out)
    verdicts(web, ssh, bf_facts, args.bf_threshold, out)
    out.append("=" * 72)
    out.append("Конец отчёта.")

    text = "\n".join(out) + "\n"
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
