#!/usr/bin/env python3
"""Оценка безопасности кода по формальной методике (лабораторная работа 7).

Сравниваются две реализации одного функционала (хранилище данных из ЛР3):

* ``own/``      -- «свой алгоритм» (safe-подход ЛР3);
* ``provided/`` -- «предоставленный алгоритм» (написан для ЛР7 с типовыми
  дефектами: secrets в str, weak PRNG для ключа, MD5 для паролей, логирование
  секретов, отсутствие затирания и валидации).

Методика: 5 критериев (C1..C5), для каждого -- способ проверки, метрика,
шкала 0..5 и вес. Проверки статические (AST-анализ кода) и динамические
(негативные прогоны, дампы памяти gdb gcore + поиск маркеров, нагрузочный
тест, анализ логов). Всё выполняется внутри контейнера; артефакты ->
``demo_output/``. Запуск: ``python3 app/evaluate.py``.
"""

from __future__ import annotations

import ast
import json
import math
import os
import re
import select
import subprocess
import sys
import time
from collections import Counter

APP_DIR = os.path.dirname(os.path.abspath(__file__))
WORK_DIR = os.path.dirname(APP_DIR)
OUT_DIR = os.path.join(WORK_DIR, "demo_output")
DUMPS_DIR = os.path.join(OUT_DIR, "dumps")
LOGS_DIR = os.path.join(OUT_DIR, "logs")

IMPLS = {
    "own": os.path.join(APP_DIR, "own", "main.py"),
    "provided": os.path.join(APP_DIR, "provided", "main.py"),
}
IMPL_TITLES = {"own": "own (свой алгоритм, ЛР3 safe)", "provided": "provided (предоставленный алгоритм)"}

TRUNCATE_LIMIT = 48 * 1024 * 1024
TRUNCATE_TO = 16 * 1024 * 1024

SECRET_NAMES = ("MASTER", "SECRET_A", "PASSWORD_B", "SECRET_D", "SECRET_E")


# ===========================================================================
# Управление дочерним процессом (тот же протокол [ok]/[err], что в ЛР3)
# ===========================================================================

class AppSession:
    def __init__(self, impl: str, transcript_path: str, env_extra: dict | None = None) -> None:
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        if impl == "provided":
            env.setdefault("PROVIDED_LOG", os.path.join(LOGS_DIR, "provided.log"))
        self.transcript_path = transcript_path
        self.proc = subprocess.Popen(
            [sys.executable, IMPLS[impl]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
            env=env,
        )
        self.fd = self.proc.stdout.fileno()
        self.buf = b""
        self.tr = open(transcript_path, "a", encoding="utf-8")
        self.dead = False

    def _readline(self, timeout: float = 120.0) -> str | None:
        deadline = time.monotonic() + timeout
        while True:
            if b"\n" in self.buf:
                raw, self.buf = self.buf.split(b"\n", 1)
                text = raw.decode("utf-8", "replace").rstrip("\r")
                self.tr.write(text + "\n")
                self.tr.flush()
                return text
            if self.dead:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("нет ответа за отведённое время")
            ready, _, _ = select.select([self.fd], [], [], min(0.5, remaining))
            if ready:
                chunk = os.read(self.fd, 65536)
                if not chunk:
                    self.dead = True
                    if self.buf:
                        text = self.buf.decode("utf-8", "replace").rstrip("\r")
                        self.buf = b""
                        self.tr.write(text + "\n")
                        self.tr.flush()
                        return text
                    return None
                self.buf += chunk

    def send(self, line: str, *, mask: bool = False) -> None:
        shown = "<значение скрыто (см. tokens.txt)>" if mask else line
        self.tr.write(f">>> {shown}\n")
        self.tr.flush()
        self.proc.stdin.write((line + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def expect_result(self, timeout: float = 180.0) -> str:
        while True:
            line = self._readline(timeout)
            if line is None:
                raise RuntimeError("процесс завершился")
            if "[ok]" in line or "[err]" in line:
                return line

    def read_banner(self) -> str:
        line = self._readline(60)
        if line is None:
            raise RuntimeError("нет баннера")
        return line

    def drain_until_exit(self, timeout: float = 60.0) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self.dead:
            if self._readline(3) is None:
                break
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.tr.write(f"### [driver] процесс завершён, код {self.proc.returncode}\n")
        self.tr.close()
        return self.proc.returncode

    def close(self) -> None:
        if not self.tr.closed:
            if not self.dead:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            self.tr.close()


def login(impl: str, session: AppSession, master: str) -> str:
    banner = session.read_banner()
    session.tr.write(f"### [driver] старт: {banner}\n")
    session.send(master, mask=True)
    return banner


# ===========================================================================
# Маркеры секретов
# ===========================================================================

def make_token(prefix: str) -> str:
    return f"{prefix}-{os.urandom(6).hex().upper()}"


def generate_tokens() -> dict[str, str]:
    return {
        "MASTER": make_token("MP"),
        "SECRET_A": make_token("CARD"),
        "PASSWORD_B": make_token("PWD"),
        "PUBLIC_C": "NOTE-PUBLIC-" + os.urandom(4).hex().upper(),
        "SECRET_D": make_token("CARD"),
        "SECRET_E": make_token("CARD"),
    }


# ===========================================================================
# C2: динамическая проверка lifetime секретов -- дампы в трёх точках
# ===========================================================================

def run_dump_scenario(impl: str, tokens: dict[str, str]) -> dict[str, str]:
    core = {
        point: os.path.join(DUMPS_DIR, f"{impl}_{label}.core")
        for point, label in (("p1", "p1_add"), ("p2", "p2_update"), ("p3", "p3_delete"))
    }
    transcript = os.path.join(DUMPS_DIR, f"session_{impl}_dump.transcript.txt")
    if os.path.exists(transcript):
        os.remove(transcript)
    session = AppSession(impl, transcript)
    print(f"[evaluate] дампы: {impl}")
    try:
        login(impl, session, tokens["MASTER"])
        session.send("noop")
        session.expect_result()
        session.send("add secret doc1")
        session.send(tokens["SECRET_A"], mask=True)
        session.expect_result()
        session.send("add password pwd1")
        session.send(tokens["PASSWORD_B"], mask=True)
        session.expect_result()
        session.send("add public note1")
        session.send(tokens["PUBLIC_C"], mask=False)
        session.expect_result()
        session.send("add secret doc2")
        session.send(tokens["SECRET_D"], mask=True)
        session.expect_result()
        session.send(f"dumpcore {core['p1']}")
        line = session.expect_result()
        if "[ok]" not in line:
            raise RuntimeError(f"dumpcore p1 failed: {line}")
        session.send("update doc1")
        session.send(tokens["SECRET_E"], mask=True)
        session.expect_result()
        session.send(f"dumpcore {core['p2']}")
        line = session.expect_result()
        if "[ok]" not in line:
            raise RuntimeError(f"dumpcore p2 failed: {line}")
        session.send("delete doc1")
        session.expect_result()
        session.send("delete doc2")
        session.expect_result()
        session.send("delete pwd1")
        session.expect_result()
        session.send(f"dumpcore {core['p3']}")
        line = session.expect_result()
        if "[ok]" not in line:
            raise RuntimeError(f"dumpcore p3 failed: {line}")
        session.send("quit")
        rc = session.drain_until_exit()
        if rc != 0:
            print(f"[evaluate] предупреждение: {impl} завершился с кодом {rc}")
    finally:
        session.close()
    return core


def analyze_dump(core_path: str, tokens: dict[str, str]) -> dict[str, int]:
    strings_path = core_path + ".strings.txt"
    with open(strings_path, "wb") as out:
        subprocess.run(["strings", "-a", core_path], stdout=out, check=True)
    counts = {name: 0 for name in tokens}
    matches: dict[str, list[str]] = {name: [] for name in tokens}
    with open(strings_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for name, token in tokens.items():
                if token in line:
                    counts[name] += 1
                    if len(matches[name]) < 4:
                        matches[name].append(line.rstrip())
    with open(core_path + ".matches.txt", "w", encoding="utf-8") as out:
        out.write(f"# Совпадения маркеров в {os.path.basename(core_path)}\n")
        for name in tokens:
            out.write(f"\n## {name} (найдено строк: {counts[name]})\n")
            for m in matches[name]:
                out.write(m[:400] + "\n")
    return counts


def find_byte_offsets(core_path: str, needle: bytes, limit: int = 3) -> list[int]:
    offsets: list[int] = []
    chunk_size = 8 * 1024 * 1024
    overlap = len(needle) - 1
    pos = 0
    tail = b""
    with open(core_path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            data = tail + chunk
            start = 0
            while True:
                idx = data.find(needle, start)
                if idx < 0:
                    break
                offsets.append(pos - len(tail) + idx)
                start = idx + 1
                if len(offsets) >= limit:
                    return offsets
            tail = data[-overlap:] if overlap else b""
            pos += len(chunk)
    return offsets


def hexdump(data: bytes, base: int = 0) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hexpart:<47}  |{asc}|")
    return "\n".join(lines)


def save_evidence_windows(core_path: str, tokens: dict[str, str], counts: dict[str, int]) -> None:
    base = os.path.splitext(os.path.basename(core_path))[0]
    for name, token in tokens.items():
        if counts.get(name, 0) == 0:
            continue
        offsets = find_byte_offsets(core_path, token.encode())
        if not offsets:
            continue
        off = offsets[0]
        with open(core_path, "rb") as fh:
            fh.seek(max(0, off - 160))
            window = fh.read(len(token) + 320)
        with open(os.path.join(DUMPS_DIR, f"evidence_{base}_{name}.bin"), "wb") as fh:
            fh.write(window)
        with open(os.path.join(DUMPS_DIR, f"evidence_{base}_{name}.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"Маркер {name} = {token}\n")
            fh.write(f"Дамп: {os.path.basename(core_path)}, смещение {off} (0x{off:x})\n")
            fh.write(f"Всего вхождений (strings): {counts[name]}\n")
            fh.write("Окрестность маркера (реальные байты дампа):\n")
            fh.write(hexdump(window, base=max(0, off - 160)) + "\n")


def truncate_if_huge(core_path: str) -> None:
    if os.path.getsize(core_path) <= TRUNCATE_LIMIT:
        return
    with open(core_path, "r+b") as fh:
        fh.truncate(TRUNCATE_TO)
    with open(core_path + ".truncated-note.txt", "w", encoding="utf-8") as fh:
        fh.write(
            f"Дамп усечён до {TRUNCATE_TO} байт для хранения.\n"
            "Анализ выполнен по полному дампу до усечения (*.strings.txt, *.matches.txt).\n"
        )


# ===========================================================================
# C1: динамическая проверка обработки невалидных данных
# ===========================================================================

PROMPT_MARKERS = ("значение:", "value:", "пароль:", "password:", "новое значение:", "new value:")

# (команда, значение если приложение запросит)
NEGATIVE_CASES = [
    ("bogus_command", "probe"),
    ("add bogus bad_id", "probe"),
    ("add secret", "probe"),
    ("add secret bad id!", "probe"),
    ("get missing_id", "probe"),
    ("update missing_id", "probe-value"),
    ("delete missing_id", "probe"),
    ("verify missing_id", "probe-value"),
    ("add secret dup_id", "probe-dup"),
    ("verify s1", "probe-value"),
]


def _run_case(session: AppSession, cmd: str, value: str, timeout: float = 90.0) -> str:
    """Классификация реакции: rejected / accepted_silently / crash / timeout.

    Приглашения ввода печатаются БЕЗ перевода строки, поэтому помимо
    завершённых строк проверяем сырой буфер: как только в нём виден
    промпт -- отправляем значение. Строки протокола [ok]/[err] могут
    иметь префикс-промпт, поэтому проверяем вхождение.
    """
    session.send(cmd)
    sent_value = False
    saw_traceback = False
    deadline = time.monotonic() + timeout
    while True:
        # 1) завершённые строки
        while b"\n" in session.buf:
            raw, session.buf = session.buf.split(b"\n", 1)
            line = raw.decode("utf-8", "replace")
            session.tr.write(line + "\n")
            session.tr.flush()
            low = line.lower()
            if "[err]" in line:
                return "rejected"
            if "[ok]" in line:
                return "accepted_silently"
            if "traceback (most recent call last)" in low:
                saw_traceback = True
        # 2) промпт без перевода строки в сыром буфере? (bytes.lower() не
        #    работает для кириллицы -- сравниваем в Unicode)
        if not sent_value and session.buf:
            low_buf = session.buf.decode("utf-8", "replace").lower()
            if any(marker in low_buf for marker in PROMPT_MARKERS):
                sent_value = True
                session.send(value, mask=True)
        # 3) процесс мёртв?
        if session.dead:
            if saw_traceback:
                return "crash (необработанное исключение)"
            return "crash (process exited)"
        # 4) ждём данные
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        ready, _, _ = select.select([session.fd], [], [], min(0.5, remaining))
        if ready:
            chunk = os.read(session.fd, 65536)
            if not chunk:
                session.dead = True
            else:
                session.buf += chunk


def run_negative_battery(impl: str, tokens: dict[str, str]) -> dict:
    transcript = os.path.join(OUT_DIR, f"negative_{impl}.transcript.txt")
    if os.path.exists(transcript):
        os.remove(transcript)
    print(f"[evaluate] негативные тесты: {impl}")
    session = AppSession(impl, transcript)
    results: list[dict] = []
    restarts = 0

    def setup(ses: AppSession) -> None:
        login(impl, ses, tokens["MASTER"])
        for cmd, value in (("add secret s1", "setup-secret"), ("add secret dup_id", "setup-dup")):
            ses.send(cmd)
            ses.send(value, mask=True)
            ses.expect_result()

    try:
        setup(session)
        for cmd, value in NEGATIVE_CASES:
            outcome = _run_case(session, cmd, value)
            results.append({"case": cmd, "outcome": outcome})
            if outcome.startswith("crash") or outcome == "timeout":
                # после падения/таймаута состояние сессии ненадёжно -- перезапуск
                restarts += 1
                session.close()
                session = AppSession(impl, transcript)
                session.tr.write("### [driver] перезапуск после аварийного завершения/таймаута\n")
                setup(session)
        session.send("quit")
        session.drain_until_exit()
    finally:
        session.close()

    rejected = sum(1 for r in results if r["outcome"] == "rejected")
    accepted = sum(1 for r in results if r["outcome"] == "accepted_silently")
    crashed = sum(1 for r in results if r["outcome"].startswith("crash"))
    timeouts = sum(1 for r in results if r["outcome"] == "timeout")
    total = len(results)
    return {
        "total": total,
        "rejected": rejected,
        "accepted_silently": accepted,
        "crashes": crashed,
        "timeouts": timeouts,
        "restarts": restarts,
        "robustness": round(rejected / total, 4),
        "cases": results,
    }


# ===========================================================================
# C3/C5: статический анализ (AST)
# ===========================================================================

def _call_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def static_facts(paths: list[str]) -> dict:
    imports: set[str] = set()
    calls: set[str] = set()
    func_names: set[str] = set()
    logging_secret_args: list[str] = []
    try_count = 0
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
                for alias in node.names:
                    imports.add(f"{node.module}.{alias.name}")
            elif isinstance(node, ast.Call):
                name = _call_name(node.func)
                calls.add(name)
                # вызовы логирования с потенциально секретными аргументами
                m = re.match(r"^(?:.*[Ll]og(?:ger)?|LOG)\.(info|debug|warning|error|critical)$", name)
                if m:
                    for arg in node.args:
                        for sub in ast.walk(arg):
                            if isinstance(sub, ast.Name) and re.search(
                                r"(?i)value|secret|passw|master|key|data", sub.id
                            ):
                                logging_secret_args.append(f"{os.path.basename(path)}: {name}({sub.id})")
                            elif isinstance(sub, ast.JoinedStr):
                                for inner in sub.values:
                                    if isinstance(inner, ast.FormattedValue) and isinstance(inner.value, ast.Name) \
                                            and re.search(r"(?i)value|secret|passw|master|key|data", inner.value.id):
                                        logging_secret_args.append(f"{os.path.basename(path)}: {name}(f:{inner.value.id})")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_names.add(node.name)
            elif isinstance(node, ast.Try):
                try_count += 1

    all_names = calls | func_names
    facts = {
        "files": [os.path.relpath(p, APP_DIR) for p in paths],
        "imports": sorted(imports),
        "uses_random_module": any(imp == "random" or imp.startswith("random.") for imp in imports),
        "uses_os_urandom": any("urandom" in c for c in calls) or any("urandom" in imp for imp in imports),
        "uses_md5": any(re.search(r"(^|\.)md5$", c) for c in calls) or any(".md5" in imp for imp in imports),
        "uses_pbkdf2": any("PBKDF2HMAC" in imp or "pbkdf" in imp.lower() for imp in imports)
        or any("pbkdf" in c.lower() for c in calls),
        "uses_cryptography_lib": any(imp.split(".")[0] == "cryptography" for imp in imports),
        "uses_bytearray": "bytearray" in calls,
        "uses_input": "input" in calls,
        "has_zeroization": any(re.search(r"erase|scrub|wipe|zero", n, re.IGNORECASE) for n in all_names),
        "logging_calls_with_secret_args": sorted(set(logging_secret_args)),
        "try_except_count": try_count,
    }
    return facts


# ===========================================================================
# C3: динамическая проверка ключевого материала
# ===========================================================================

def shannon_bits_per_byte(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in Counter(data).values()), 4)


def key_quality_samples() -> dict:
    """Образцы ключевого материала от собственного генератора каждой реализации."""
    sys.path.insert(0, os.path.join(APP_DIR, "own"))
    import vault as own_vault  # noqa: PLC0415

    own_key = own_vault.derive_key("evaluation-password", os.urandom(16))
    own_stream = b"".join(own_vault.derive_key(f"pw-{i}", os.urandom(16)) for i in range(32))

    sys.path.insert(0, os.path.join(APP_DIR, "provided"))
    import store as provided_store  # noqa: PLC0415

    provided_keys = [provided_store.init_crypto(f"pw-{i}") for i in range(32)]
    provided_stream = b"".join(provided_keys)

    return {
        "own": {
            "key_len_bits": len(own_key) * 8,
            "source": "PBKDF2-HMAC-SHA256 (600000 итераций) из мастер-пароля, соль os.urandom(16)",
            "sample_hex": own_key.hex(),
            "stream_len_bytes": len(own_stream),
            "shannon_bits_per_byte": shannon_bits_per_byte(own_stream),
        },
        "provided": {
            "key_len_bits": len(provided_keys[0]) * 8,
            "source": "random.getrandbits(8) -- Mersenne Twister, weak PRNG",
            "sample_hex": provided_keys[0].hex(),
            "stream_len_bytes": len(provided_stream),
            "shannon_bits_per_byte": shannon_bits_per_byte(provided_stream),
        },
    }


# ===========================================================================
# C4: нагрузочный тест (отдельный процесс на реализацию)
# ===========================================================================

def load_test(impl: str, n: int = 2000) -> dict:
    print(f"[evaluate] нагрузочный тест: {impl} (N={n})")
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "bench_impl.py"), impl, str(n)],
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode != 0:
        return {"impl": impl, "success": False, "error": proc.stderr[-500:]}
    line = [l for l in proc.stdout.splitlines() if l.strip().startswith("{")]
    if not line:
        return {"impl": impl, "success": False, "error": "нет JSON-вывода"}
    return json.loads(line[-1])


# ===========================================================================
# Формальная методика и подсчёт баллов
# ===========================================================================

METHODOLOGY = [
    {
        "id": "C1",
        "name": "Обработка невалидных данных и аварийных ситуаций",
        "weight": 0.15,
        "check": "динамическая: батарея из 10 невалидных входов (неизвестная команда, "
                 "неверный тип/формат, лишние аргументы, операции над несуществующими "
                 "записями, дубликат, verify для не-пароля); фиксируются отклонение ([err]), "
                 "молчаливое принятие и аварийное завершение",
        "metric": "robustness = доля входов, корректно отклонённых без падения",
        "scale": "5: 100%; 4: ≥90%; 3: ≥70%; 2: ≥50%; 1: ≥30%; 0: <30%",
    },
    {
        "id": "C2",
        "name": "Lifetime секретов в памяти",
        "weight": 0.30,
        "check": "динамическая: дампы памяти (gdb gcore) в 3 точках (ввод / обновление / "
                 "удаление); strings -a + поиск 5 секретных маркеров",
        "metric": "доля секретных маркеров, НАЙДЕННЫХ в дампе после удаления (главный "
                  "индикатор остаточных данных); находки в точках ввода/обновления фиксируются",
        "scale": "5: в p3 не найдено ни одного секрета; 0: найдены все; иначе 5·(1−доля)",
    },
    {
        "id": "C3",
        "name": "Качество ключевого материала",
        "weight": 0.20,
        "check": "статическая (AST): источник случайности (os.urandom/secrets vs random), "
                 "KDF для паролей (PBKDF2/scrypt vs MD5), стандартный аутентифицированный "
                 "шифр (cryptography AES-GCM vs самодельный); динамическая: длина ключа и "
                 "энтропия байт выходного потока генератора (информационно)",
        "metric": "CSPRNG-источник (0/2) + KDF паролей (0/2) + аутентифицированный шифр (0/1)",
        "scale": "0..5 (сумма компонентов)",
    },
    {
        "id": "C4",
        "name": "Поведение под нагрузкой / на больших объёмах",
        "weight": 0.10,
        "check": "динамическая: 2000 конфиденциальных записей, фазы add/update/delete в "
                 "отдельном процессе; замер wall/CPU/RSS",
        "metric": "успешность фаз; avg мс/операцию; прирост RSS КБ/запись; замедление "
                  "удаления относительно добавления",
        "scale": "5: все фазы успешны, avg ≤5 мс/оп, ≤10 КБ/запись, delete ≤10×add; "
                 "−1 за каждое нарушение; 0 при сбое фазы",
    },
    {
        "id": "C5",
        "name": "Работа с конфиденциальными данными в ОЗУ и журналах",
        "weight": 0.25,
        "check": "статическая (AST): наличие механизма затирания (erase/scrub/wipe/zero), "
                 "вызовы логирования с секретными аргументами; динамическая: поиск 5 "
                 "секретных маркеров в журнале приложения и транскрипте сессии",
        "metric": "утечки в журналах: 3·(1−доля утёкших маркеров); затирание: 2 (есть) / 0 (нет)",
        "scale": "0..5 (сумма компонентов)",
    },
]

VERDICTS = [(4.0, "принят"), (2.5, "требует доработки"), (0.0, "отклонён")]


def verdict_for(total: float) -> str:
    for threshold, verdict in VERDICTS:
        if total >= threshold:
            return verdict
    return "отклонён"


def score_c1(neg: dict) -> int:
    r = neg["robustness"]
    for score, bound in ((5, 1.0), (4, 0.9), (3, 0.7), (2, 0.5), (1, 0.3)):
        if r >= bound:
            return score
    return 0


def score_c2(counts_by_point: dict, tokens: dict[str, str]) -> tuple[int, float]:
    p3 = counts_by_point["p3"]
    found = sum(p3[name] > 0 for name in SECRET_NAMES)
    ratio = found / len(SECRET_NAMES)
    return round(5 * (1 - ratio)), ratio


def score_c3(facts: dict) -> int:
    csprng = (facts["uses_os_urandom"] or "secrets" in facts["imports"]) and not facts["uses_random_module"]
    kdf = facts["uses_pbkdf2"] and not facts["uses_md5"]
    cipher = facts["uses_cryptography_lib"]
    return (2 if csprng else 0) + (2 if kdf else 0) + (1 if cipher else 0)


def score_c4(load: dict) -> tuple[int, dict]:
    detail: dict = {}
    if not load.get("success"):
        return 0, {"reason": "фазы не завершены", **{k: load.get(k) for k in ("error",)}}
    phases = {p["phase"]: p for p in load["phases"]}
    add, upd, dele = phases["add"], phases["update"], phases["delete"]
    avg = max(add["avg_ms"], upd["avg_ms"], dele["avg_ms"])
    rss_rec = max(add["rss_per_record_kB"], upd["rss_per_record_kB"])
    slowdown = round(dele["wall_s"] / add["wall_s"], 2) if add["wall_s"] > 0 else None
    score = 5
    if avg > 5:
        score -= 1
        detail["avg_ms_violation"] = avg
    if rss_rec > 10:
        score -= 1
        detail["rss_violation_kB"] = rss_rec
    if slowdown is not None and slowdown > 10:
        score -= 1
        detail["delete_slowdown"] = slowdown
    detail.update({"avg_ms_max": avg, "rss_per_record_kB_max": rss_rec, "delete_vs_add": slowdown})
    return max(score, 0), detail


def score_c5(facts: dict, leaked_in_logs: int, total_secrets: int) -> tuple[int, dict]:
    ratio = leaked_in_logs / total_secrets
    part_logs = round(3 * (1 - ratio))
    part_zero = 2 if facts["has_zeroization"] else 0
    return part_logs + part_zero, {
        "leaked_in_logs": leaked_in_logs,
        "total_secrets": total_secrets,
        "has_zeroization": facts["has_zeroization"],
        "logging_secret_args": facts["logging_calls_with_secret_args"],
    }


def secrets_in_artifacts(paths: list[str], tokens: dict[str, str]) -> tuple[int, dict[str, int]]:
    counts = {name: 0 for name in SECRET_NAMES}
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                for name in SECRET_NAMES:
                    if tokens[name] in line:
                        counts[name] += 1
    return sum(1 for c in counts.values() if c > 0), counts


# ===========================================================================
# Отчёт
# ===========================================================================

def build_report(results: dict, tokens: dict[str, str]) -> str:
    points = (("p1", "после ввода"), ("p2", "после обновления"), ("p3", "после удаления"))
    lines: list[str] = []
    lines += [
        "# Оценка безопасности кода по методике (ЛР7)",
        "",
        "Сравнение: `own` -- свой алгоритм (safe-подход ЛР3) и `provided` -- предоставленный",
        "алгоритм. Все значения таблиц -- реальные результаты проверок, выполненных в",
        "контейнере (статический AST-анализ, негативные прогоны, дампы gdb gcore, нагрузочный",
        "тест). Маркеры прогона: `dumps/tokens.txt`.",
        "",
        "## 1. Методика (критерии, проверка, метрика, шкала)",
        "",
        "| ID | Критерий | Вес | Способ проверки | Метрика | Шкала 0–5 |",
        "|---|---|---|---|---|---|",
    ]
    for c in METHODOLOGY:
        lines.append(
            f"| {c['id']} | {c['name']} | {c['weight']:.2f} | {c['check']} | {c['metric']} | {c['scale']} |"
        )
    lines += [
        "",
        "Итог: `Σ балл(критерия)·вес` (0–5). Вердикты: ≥4.0 — **принят**;",
        "2.5–3.9 — **требует доработки**; <2.5 — **отклонён**.",
        "",
        "## 2. Статический анализ (AST) -- факты",
        "",
        "| Факт | own | provided |",
        "|---|---|---|",
    ]
    fact_rows = [
        ("cryptography (AES-GCM/PBKDF2)", "uses_cryptography_lib"),
        ("os.urandom (CSPRNG)", "uses_os_urandom"),
        ("модуль random (weak PRNG)", "uses_random_module"),
        ("PBKDF2 (KDF паролей)", "uses_pbkdf2"),
        ("MD5 (слабый хэш)", "uses_md5"),
        ("bytearray (изменяемые буферы)", "uses_bytearray"),
        ("механизм затирания (erase/scrub/zero)", "has_zeroization"),
        ("input() (буферизация с опережением)", "uses_input"),
    ]
    for label, key in fact_rows:
        lines.append(f"| {label} | {results['static']['own'][key]} | {results['static']['provided'][key]} |")
    lines += ["", "try/except: " + f"own={results['static']['own']['try_except_count']}, "
              f"provided={results['static']['provided']['try_except_count']}"]
    for impl in ("own", "provided"):
        args = results["static"][impl]["logging_calls_with_secret_args"]
        lines.append(f"Логирование секретных аргументов ({impl}): " + (", ".join(args) if args else "не обнаружено"))
    lines += [
        "",
        "## 3. C1 -- негативные прогоны (10 невалидных входов)",
        "",
        "| Показатель | own | provided |",
        "|---|---:|---:|",
    ]
    for key in ("rejected", "accepted_silently", "crashes", "timeouts", "restarts", "robustness"):
        lines.append(f"| {key} | {results['negative']['own'][key]} | {results['negative']['provided'][key]} |")
    lines += [
        "",
        "Детальные исходы по каждому входу: `negative_own.transcript.txt`,",
        "`negative_provided.transcript.txt` (реальные транскрипты), JSON в",
        "`evaluation_results.json`.",
        "",
        "## 4. C2 -- дампы памяти (3 точки × 2 реализации)",
        "",
        "Число строк с маркером (strings -a + grep):",
        "",
        "| Маркер | " + " | ".join(f"{impl}·{label}" for impl in ("own", "provided") for point, label in points) + " |",
        "|---|" + "---|" * 6,
    ]
    for name in ("MASTER", "SECRET_A", "PASSWORD_B", "PUBLIC_C", "SECRET_D", "SECRET_E"):
        row = f"| {name} |"
        for impl in ("own", "provided"):
            for point, _ in points:
                row += f" {results['dumps'][impl][point][name]} |"
        lines.append(row)
    lines += [
        "",
        "Секретных маркеров в дампе после удаления (p3): own -- "
        f"{results['c2_detail']['own']['found_p3']} из 5, provided -- "
        f"{results['c2_detail']['provided']['found_p3']} из 5.",
        "Окна памяти с реальными байтами вокруг находок: `dumps/evidence_*.txt`.",
        "",
        "## 5. C3 -- ключевой материал",
        "",
        "| Параметр | own | provided |",
        "|---|---|---|",
    ]
    for key, label in (
        ("key_len_bits", "Длина ключа, бит"),
        ("source", "Источник"),
        ("shannon_bits_per_byte", "Энтропия выходного потока, бит/байт (1024 Б)"),
        ("sample_hex", "Пример ключа (hex)"),
    ):
        lines.append(f"| {label} | {results['keys']['own'][key]} | {results['keys']['provided'][key]} |")
    lines += [
        "",
        "Примечание: частотная энтропия у обоих источников близка к 8 бит/байт --",
        "распределение байт НЕ выявляет слабый PRNG; слабый источник выявляется",
        "только аудитом источника (AST): `random.getrandbits` (Mersenne Twister,",
        "предсказуемый) против PBKDF2/os.urandom.",
        "",
        "## 6. C4 -- нагрузочный тест (2000 записей)",
        "",
        "| Фаза | own: avg мс/оп, ΔRSS КБ | provided: avg мс/оп, ΔRSS КБ |",
        "|---|---|---|",
    ]
    load_own = {p["phase"]: p for p in results["load"]["own"]["phases"]}
    load_prv = {p["phase"]: p for p in results["load"]["provided"]["phases"]}
    for phase in ("add", "update", "delete"):
        lines.append(
            f"| {phase} | {load_own[phase]['avg_ms']} мс, {load_own[phase]['drss_kB']} КБ "
            f"| {load_prv[phase]['avg_ms']} мс, {load_prv[phase]['drss_kB']} КБ |"
        )
    lines += [
        "",
        f"own: success={results['load']['own']['success']}, детали: {results['c4_detail']['own']}",
        f"provided: success={results['load']['provided']['success']}, детали: {results['c4_detail']['provided']}",
        "",
        "## 7. C5 -- конфиденциальные данные в журналах и ОЗУ",
        "",
        f"Маркеров, найденных в журнале/транскрипте: own -- {results['c5_detail']['own']['leaked_in_logs']} из 5, "
        f"provided -- {results['c5_detail']['provided']['leaked_in_logs']} из 5 "
        "(журнал provided: `logs/provided.log`; транскрипты: `dumps/session_*_dump.transcript.txt`).",
        f"Механизм затирания (статически): own -- {results['static']['own']['has_zeroization']}, "
        f"provided -- {results['static']['provided']['has_zeroization']}.",
        "",
        "## 8. Итоговая таблица",
        "",
        "| Критерий | Вес | own | provided |",
        "|---|---|---:|---:|",
    ]
    total = {"own": 0.0, "provided": 0.0}
    for c in METHODOLOGY:
        cid = c["id"].lower()
        own_s = results["scores"]["own"][cid]
        prv_s = results["scores"]["provided"][cid]
        total["own"] += own_s * c["weight"]
        total["provided"] += prv_s * c["weight"]
        lines.append(f"| {c['id']} {c['name']} | {c['weight']:.2f} | {own_s} | {prv_s} |")
    lines += [
        f"| **Итог (0–5)** | 1.00 | **{total['own']:.2f}** | **{total['provided']:.2f}** |",
        f"| **Вердикт** | | **{verdict_for(total['own'])}** | **{verdict_for(total['provided'])}** |",
        "",
        "Файлы-доказательства: `dumps/*.core`, `dumps/*.strings.txt`, `dumps/*.matches.txt`,",
        "`dumps/evidence_*.txt`, `negative_*.transcript.txt`, `dumps/session_*_dump.transcript.txt`,",
        "`logs/provided.log`, `load_own.json`, `load_provided.json`, `evaluation_results.json`.",
        "",
    ]
    return "\n".join(lines)


# ===========================================================================
# Главная
# ===========================================================================

def chown_tree(root: str, uid: int, gid: int) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            try:
                os.chown(os.path.join(dirpath, name), uid, gid)
            except OSError:
                pass


def main() -> int:
    for d in (OUT_DIR, DUMPS_DIR, LOGS_DIR):
        os.makedirs(d, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(OUT_DIR, topdown=False):
        for name in filenames:
            os.remove(os.path.join(dirpath, name))
        for name in dirnames:
            os.rmdir(os.path.join(dirpath, name))
    for d in (DUMPS_DIR, LOGS_DIR):
        os.makedirs(d, exist_ok=True)

    print("=== ЛР7: оценка безопасности кода по методике ===")
    tokens = generate_tokens()
    with open(os.path.join(DUMPS_DIR, "tokens.txt"), "w", encoding="utf-8") as fh:
        fh.write("# Маркеры секретов прогона\n")
        for name, token in tokens.items():
            fh.write(f"{name}={token}\n")

    results: dict = {"tokens": tokens}

    # статический анализ
    print("[evaluate] статический анализ (AST)")
    results["static"] = {
        impl: static_facts([os.path.join(APP_DIR, impl, name)
                            for name in sorted(os.listdir(os.path.join(APP_DIR, impl)))
                            if name.endswith(".py")])
        for impl in ("own", "provided")
    }

    # динамические проверки по реализациям
    results["dumps"] = {}
    results["negative"] = {}
    for impl in ("own", "provided"):
        core = run_dump_scenario(impl, tokens)
        results["dumps"][impl] = {
            point: analyze_dump(path, tokens) for point, path in core.items()
        }
        for path in core.values():
            save_evidence_windows(path, tokens, results["dumps"][impl][
                {v: k for k, v in core.items()}[path]
            ])
            truncate_if_huge(path)
        results["negative"][impl] = run_negative_battery(impl, tokens)

    # ключевой материал
    print("[evaluate] ключевой материал")
    results["keys"] = key_quality_samples()

    # нагрузочный тест
    results["load"] = {impl: load_test(impl, 2000) for impl in ("own", "provided")}
    with open(os.path.join(OUT_DIR, "load_own.json"), "w", encoding="utf-8") as fh:
        json.dump(results["load"]["own"], fh, ensure_ascii=False, indent=2)
    with open(os.path.join(OUT_DIR, "load_provided.json"), "w", encoding="utf-8") as fh:
        json.dump(results["load"]["provided"], fh, ensure_ascii=False, indent=2)

    # баллы
    results["c2_detail"] = {}
    results["c3_detail"] = {}
    results["c4_detail"] = {}
    results["c5_detail"] = {}
    results["scores"] = {"own": {}, "provided": {}}
    for impl in ("own", "provided"):
        s = results["scores"][impl]
        s["c1"] = score_c1(results["negative"][impl])

        c2_score, found = score_c2(results["dumps"][impl], tokens)
        p3 = results["dumps"][impl]["p3"]
        results["c2_detail"][impl] = {
            "found_p3": sum(p3[name] > 0 for name in SECRET_NAMES),
            "ratio_p3": found,
        }
        s["c2"] = c2_score

        s["c3"] = score_c3(results["static"][impl])

        c4_score, c4_detail = score_c4(results["load"][impl])
        s["c4"] = c4_score
        results["c4_detail"][impl] = c4_detail

        leaked, leaked_counts = secrets_in_artifacts(
            [os.path.join(LOGS_DIR, f"{impl}.log"),
             os.path.join(DUMPS_DIR, f"session_{impl}_dump.transcript.txt")],
            tokens,
        )
        c5_score, c5_detail = score_c5(results["static"][impl], leaked, len(SECRET_NAMES))
        c5_detail["leaked_counts"] = leaked_counts
        s["c5"] = c5_score
        results["c5_detail"][impl] = c5_detail

    report = build_report(results, tokens)
    with open(os.path.join(OUT_DIR, "evaluation_report.md"), "w", encoding="utf-8") as fh:
        fh.write(report)
    with open(os.path.join(OUT_DIR, "evaluation_results.json"), "w", encoding="utf-8") as fh:
        json.dump({k: v for k, v in results.items()}, fh, ensure_ascii=False, indent=2, default=str)

    print("\n" + report.split("## 8. Итоговая таблица")[1])
    uid = int(os.getenv("HOST_UID", "0"))
    gid = int(os.getenv("HOST_GID", "0"))
    if uid and gid:
        chown_tree(OUT_DIR, uid, gid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
