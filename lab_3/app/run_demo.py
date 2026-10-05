#!/usr/bin/env python3
"""Драйвер демонстрации лабораторной работы 3 (выполняется в контейнере).

Этапы:
  1. интерактивная сессия с приложением в режимах safe и unsafe
     (реальный stdin/stdout протокол, транскрипты -> demo_output);
  2. bench RSS/CPU -> demo_output/metrics.csv, metrics.md;
  3. сценарий дампов: для каждого режима снимаются 3 дампа (gdb gcore)
     после ввода, после обновления и после удаления; затем по ПОЛНЫМ
     дампам выполняется `strings -a` и поиск маркеров секретов;
  4. сводный анализ -> demo_output/dumps/dumps_analysis.md.

Маркеры секретов генерируются случайно (не константы в коде), передаются
приложению через stdin и рассылаются «не вперёд» -- значение очередной
операции отправляется только после того, как предыдущий шаг подтверждён,
чтобы ещё не введённые секреты не попадали в буфер stdin до дампа.
"""

from __future__ import annotations

import os
import select
import subprocess
import sys
import time

APP_DIR = os.path.dirname(os.path.abspath(__file__))
WORK_DIR = os.path.dirname(APP_DIR)
OUT_DIR = os.path.join(WORK_DIR, "demo_output")
DUMPS_DIR = os.path.join(OUT_DIR, "dumps")

# Хранение: если дамп больше лимита -- усекаем (анализ уже выполнен по полному)
TRUNCATE_LIMIT = 48 * 1024 * 1024
TRUNCATE_TO = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Управление дочерним процессом приложения
# ---------------------------------------------------------------------------

class AppSession:
    """Диалог с приложением через реальные stdin/stdout (с таймаутами)."""

    def __init__(self, mode: str, transcript_path: str) -> None:
        self.transcript_path = transcript_path
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(APP_DIR, "main.py"), "--mode", mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self.fd = self.proc.stdout.fileno()
        self.buf = b""
        self.tr = open(transcript_path, "w", encoding="utf-8")
        self.dead = False

    # -- внутреннее ------------------------------------------------------

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
                raise TimeoutError("приложение не ответило за отведённое время")
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

    # -- протокол --------------------------------------------------------

    def send(self, line: str, *, mask: bool = False) -> None:
        shown = "<значение скрыто (см. tokens.txt)>" if mask else line
        self.tr.write(f">>> {shown}\n")
        self.tr.flush()
        assert self.proc.stdin is not None
        self.proc.stdin.write((line + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def expect_result(self, timeout: float = 180.0) -> str:
        """Читает строки вывода, пока не встретит [ok]/[err] (конец команды).

        Строка результата может быть снабжена префиксом-приглашением без
        перевода строки (``vault[safe]> ...``), поэтому проверяем вхождение.
        """
        while True:
            line = self._readline(timeout)
            if line is None:
                raise RuntimeError("процесс приложения завершился раньше времени")
            if "[ok]" in line or "[err]" in line:
                return line

    def read_banner(self) -> str:
        line = self._readline(60)
        if line is None:
            raise RuntimeError("приложение не вывело баннер")
        return line

    def drain_until_exit(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.dead:
                break
            line = self._readline(5)
            if line is None:
                break
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.tr.write(f"### [driver] процесс завершён, код {self.proc.returncode}\n")
        self.tr.close()

    def close(self) -> None:
        if self.tr.closed:
            return
        if not self.dead:
            self.proc.kill()
            self.proc.wait()
        self.tr.close()


# ---------------------------------------------------------------------------
# Шаг 1: интерактивная сессия (демонстрация UI и обработки ошибок)
# ---------------------------------------------------------------------------

def interactive_steps(tokens: dict[str, str]) -> list[tuple[str, str | None, bool]]:
    """(команда, значение|None, маскировать значение в транскрипте)."""
    return [
        ("help", None, False),
        ("stats", None, False),
        ("add secret card1", tokens["SECRET_A"], True),
        ("add password pwd1", tokens["PASSWORD_B"], True),
        ("add public note1", tokens["PUBLIC_C"], False),
        ("add secret doc2", tokens["SECRET_D"], True),
        ("list", None, False),
        ("get card1", None, False),
        ("verify pwd1", tokens["PASSWORD_B"], True),
        ("update card1", tokens["SECRET_E"], True),
        ("get card1", None, False),
        # -- невалидный ввод --
        ("add secret card1", "дубликат-значение", True),
        ("add bogus bad_id", None, False),
        ("add secret", None, False),
        ("add secret bad id!", None, False),
        ("get missing_id", None, False),
        ("update missing_id", None, False),
        ("delete missing_id", None, False),
        ("verify card1", None, False),
        ("bogus_command", None, False),
        # -- удаление --
        ("delete card1", None, False),
        ("get card1", None, False),
        ("list", None, False),
        ("stats", None, False),
    ]


def run_interactive_session(mode: str, tokens: dict[str, str]) -> None:
    prefix = os.path.join(OUT_DIR, f"session_{mode}")
    session = AppSession(mode, prefix + ".transcript.txt")
    print(f"[demo] интерактивная сессия: режим {mode}")
    try:
        banner = session.read_banner()
        session.tr.write(f"### [driver] старт приложения: {banner}\n")
        session.send("MASTER-" + os.urandom(8).hex(), mask=True)
        results: list[tuple[str, str]] = []
        for command, value, mask in interactive_steps(tokens):
            session.send(command)
            if value is not None:
                session.send(value, mask=mask)
            results.append((command, session.expect_result()))
        session.send("quit")
        session.drain_until_exit()
    finally:
        session.close()
    ok = sum(1 for _, line in results if "[ok]" in line)
    err = sum(1 for _, line in results if "[err]" in line)
    print(f"[demo] сессия {mode}: команд={len(results)}, ok={ok}, err={err} "
          f"(корректная обработка невалидного ввода)")


# ---------------------------------------------------------------------------
# Шаг 2: bench
# ---------------------------------------------------------------------------

def run_bench() -> None:
    print("[demo] bench: замеры RSS и CPU")
    with open(os.path.join(OUT_DIR, "bench_log.txt"), "w", encoding="utf-8") as log:
        proc = subprocess.run(
            [sys.executable, os.path.join(APP_DIR, "bench.py"), OUT_DIR],
            stdout=log, stderr=subprocess.STDOUT, timeout=1200,
        )
    if proc.returncode != 0:
        raise RuntimeError("bench завершился с ошибкой, см. demo_output/bench_log.txt")


# ---------------------------------------------------------------------------
# Шаг 3: дампы памяти в трёх точках
# ---------------------------------------------------------------------------

def make_token(prefix: str) -> str:
    return f"{prefix}-{os.urandom(6).hex().upper()}"


def generate_tokens() -> dict[str, str]:
    return {
        "MASTER": make_token("MP"),       # мастер-пароль
        "SECRET_A": make_token("CARD"),   # конфиденциальная запись (AES-GCM)
        "PASSWORD_B": make_token("PWD"),  # пароль (PBKDF2)
        "PUBLIC_C": "NOTE-PUBLIC-" + os.urandom(4).hex().upper(),  # открытые данные
        "SECRET_D": make_token("CARD"),   # вторая конфиденциальная запись
        "SECRET_E": make_token("CARD"),   # новое значение при update
    }


def run_dump_scenario(mode: str, tokens: dict[str, str]) -> dict[str, str]:
    """Три точки дампа: после ввода, после обновления, после удаления."""
    core = {
        name: os.path.join(DUMPS_DIR, f"{mode}_{point}.core")
        for name, point in (
            ("p1", "p1_add"), ("p2", "p2_update"), ("p3", "p3_delete")
        )
    }
    transcript = os.path.join(DUMPS_DIR, f"session_{mode}_dump.transcript.txt")
    session = AppSession(mode, transcript)
    print(f"[demo] сценарий дампов: режим {mode}")
    try:
        banner = session.read_banner()
        session.tr.write(f"### [driver] старт приложения: {banner}\n")
        session.send(tokens["MASTER"], mask=True)
        session.send("noop")
        session.expect_result()
        # точка 1: ввод данных
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
        session.send("list")
        session.expect_result()
        session.send(f"dumpcore {core['p1']}")
        line = session.expect_result()
        if "[ok]" not in line:
            raise RuntimeError(f"dumpcore p1 не выполнен: {line}")
        # точка 2: обновление (старое+новое значение)
        session.send("update doc1")
        session.send(tokens["SECRET_E"], mask=True)
        session.expect_result()
        session.send(f"dumpcore {core['p2']}")
        line = session.expect_result()
        if "[ok]" not in line:
            raise RuntimeError(f"dumpcore p2 не выполнен: {line}")
        # точка 3: удаление конфиденциальных данных
        session.send("delete doc1")
        session.expect_result()
        session.send("delete doc2")
        session.expect_result()
        session.send("delete pwd1")
        session.expect_result()
        session.send(f"dumpcore {core['p3']}")
        line = session.expect_result()
        if "[ok]" not in line:
            raise RuntimeError(f"dumpcore p3 не выполнен: {line}")
        session.send("quit")
        session.drain_until_exit()
    finally:
        session.close()
    for name, path in core.items():
        if not os.path.exists(path):
            raise RuntimeError(f"дамп не создан: {path}")
        size = os.path.getsize(path)
        print(f"[demo] дамп {mode}/{name}: {path} ({size / 1024 / 1024:.1f} МиБ)")
    return core


# ---------------------------------------------------------------------------
# Шаг 4: анализ дампов (strings + поиск маркеров)
# ---------------------------------------------------------------------------

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
        out.write(f"# команда: strings -a {os.path.basename(core_path)} | grep -F <маркер>\n")
        for name in tokens:
            out.write(f"\n## {name} (найдено строк: {counts[name]})\n")
            for m in matches[name]:
                out.write(m[:400] + "\n")
    return counts


def find_byte_offsets(core_path: str, needle: bytes, limit: int = 3) -> list[int]:
    """Позиции needle в сыром дампе (для извлечения окна-доказательства)."""
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


def save_evidence_windows(
    core_path: str, tokens: dict[str, str], counts: dict[str, int]
) -> list[str]:
    """Сохраняет hex-окрестность найденных маркеров (реальные байты дампа)."""
    saved = []
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
        bin_path = os.path.join(DUMPS_DIR, f"evidence_{base}_{name}.bin")
        txt_path = os.path.join(DUMPS_DIR, f"evidence_{base}_{name}.txt")
        with open(bin_path, "wb") as fh:
            fh.write(window)
        with open(txt_path, "w", encoding="utf-8") as fh:
            fh.write(f"Маркер {name} = {token}\n")
            fh.write(f"Дамп: {os.path.basename(core_path)}, смещение {off} (0x{off:x})\n")
            fh.write(f"Всего вхождений (strings): {counts[name]}\n")
            fh.write("Окрестность маркера (реальные байты дампа):\n")
            fh.write(hexdump(window, base=max(0, off - 160)) + "\n")
        saved.append(txt_path)
    return saved


def truncate_if_huge(core_path: str) -> str | None:
    size = os.path.getsize(core_path)
    if size <= TRUNCATE_LIMIT:
        return None
    with open(core_path, "r+b") as fh:
        fh.truncate(TRUNCATE_TO)
    note = core_path + ".truncated-note.txt"
    with open(note, "w", encoding="utf-8") as fh:
        fh.write(
            f"Исходный дамп {size} байт усечён до {TRUNCATE_TO} байт для хранения.\n"
            "Анализ (strings/поиск маркеров) выполнен ПО ПОЛНОМУ дампу до усечения;\n"
            "реальный вывод анализа: *.strings.txt и *.matches.txt рядом.\n"
        )
    return note


def build_analysis_md(
    dumps: dict[str, dict[str, str]],
    counts: dict[str, dict[str, dict[str, int]]],
    tokens: dict[str, str],
) -> None:
    """dumps[mode][point] = путь; counts[mode][point][token] = число строк."""
    points = [("p1", "после ввода данных"), ("p2", "после обновления"), ("p3", "после удаления")]
    lines = [
        "# Анализ дампов оперативной памяти (3 точки x 2 режима)",
        "",
        "Все значения в таблицах ниже -- реальный вывод анализа, выполненного",
        "в контейнере по ПОЛНЫМ core-файлам (gdb gcore). Методика:",
        "",
        "```",
        "gdb -p <pid> -batch -ex 'gcore <файл>'   # снимок памяти процесса",
        "strings -a <файл.core> > *.strings.txt   # все печатные строки дампа",
        "grep -F <маркер> *.strings.txt           # поиск маркеров секретов",
        "```",
        "",
        "Полные списки строк дампов: `*.strings.txt`; совпадения: `*.matches.txt`;",
        "журналы gdb: `*.gdb.log`; окна памяти с найденными маркерами: `evidence_*.txt`.",
        "",
        "## Маркеры (сгенерированы случайно во время демо)",
        "",
        "| Маркер | Значение | Класс данных |",
        "|---|---|---|",
        f"| MASTER | `{tokens['MASTER']}` | мастер-пароль |",
        f"| SECRET_A | `{tokens['SECRET_A']}` | конфиденциальные данные |",
        f"| PASSWORD_B | `{tokens['PASSWORD_B']}` | пароль |",
        f"| PUBLIC_C | `{tokens['PUBLIC_C']}` | неконфиденциальные данные |",
        f"| SECRET_D | `{tokens['SECRET_D']}` | конфиденциальные данные |",
        f"| SECRET_E | `{tokens['SECRET_E']}` | новое значение при обновлении |",
        "",
        "## Число найденных строк с маркером (strings + grep)",
        "",
    ]
    header = "| Маркер |"
    sep = "|---|"
    for mode in ("safe", "unsafe"):
        for point, label in points:
            header += f" {mode}·{label} |"
            sep += "---|"
    lines += [header, sep]
    for token_name in ("MASTER", "SECRET_A", "PASSWORD_B", "PUBLIC_C", "SECRET_D", "SECRET_E"):
        row = f"| {token_name} |"
        for mode in ("safe", "unsafe"):
            for point, _ in points:
                cnt = counts[mode][point][token_name]
                row += f" {cnt} |"
        lines.append(row)
    lines += [
        "",
        "## Выводы по таблице (сформированы по фактическим числам выше)",
        "",
    ]
    for mode in ("safe", "unsafe"):
        p3 = counts[mode]["p3"]
        p1 = counts[mode]["p1"]
        secrets_p3 = sum(
            p3[name] for name in ("MASTER", "SECRET_A", "PASSWORD_B", "SECRET_D", "SECRET_E")
        )
        secrets_p1 = sum(
            p1[name] for name in ("MASTER", "SECRET_A", "PASSWORD_B", "SECRET_D", "SECRET_E")
        )
        lines.append(
            f"* режим **{mode}**: секретных маркеров в дампе после ввода -- {secrets_p1}, "
            f"после удаления -- {secrets_p3};"
        )
    lines += [
        "",
        "Интерпретация приведена в отчёте (report/report.md, раздел про дампы).",
        "",
    ]
    with open(os.path.join(DUMPS_DIR, "dumps_analysis.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ---------------------------------------------------------------------------
# Служебное
# ---------------------------------------------------------------------------

def chown_tree(root: str, uid: int, gid: int) -> None:
    os.chown(root, uid, gid)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            try:
                os.chown(os.path.join(dirpath, name), uid, gid)
            except OSError:
                pass


def clean_output_dir() -> None:
    """demo_output -- только свежие артефакты текущего запуска."""
    for dirpath, dirnames, filenames in os.walk(OUT_DIR, topdown=False):
        for name in filenames:
            os.remove(os.path.join(dirpath, name))
        for name in dirnames:
            os.rmdir(os.path.join(dirpath, name))
    os.makedirs(DUMPS_DIR, exist_ok=True)


def main() -> int:
    os.makedirs(DUMPS_DIR, exist_ok=True)
    clean_output_dir()
    print("=== Лабораторная работа 3: демонстрация (всё внутри контейнера) ===")

    tokens = generate_tokens()
    with open(os.path.join(DUMPS_DIR, "tokens.txt"), "w", encoding="utf-8") as fh:
        fh.write("# Маркеры, использованные в демо (введены через stdin)\n")
        for name, token in tokens.items():
            fh.write(f"{name}={token}\n")

    # 1. интерактивные сессии
    run_interactive_session("safe", tokens)
    run_interactive_session("unsafe", tokens)

    # 2. bench
    run_bench()

    # 3-4. дампы и их анализ
    all_dumps: dict[str, dict[str, str]] = {}
    all_counts: dict[str, dict[str, dict[str, int]]] = {}
    for mode in ("safe", "unsafe"):
        core = run_dump_scenario(mode, tokens)
        all_dumps[mode] = core
        all_counts[mode] = {}
        for point, path in core.items():
            all_counts[mode][point] = analyze_dump(path, tokens)
            save_evidence_windows(path, tokens, all_counts[mode][point])
            note = truncate_if_huge(path)
            if note:
                print(f"[demo] дамп усечён для хранения: {note}")

    build_analysis_md(all_dumps, all_counts, tokens)

    print("\n=== Сводка по дампам (число строк с маркером) ===")
    header = f"{'маркер':<12}" + "".join(f"{m}_{p:<10}" for m in ("safe", "unsafe") for p in ("p1", "p2", "p3"))
    print(header)
    for name in ("MASTER", "SECRET_A", "PASSWORD_B", "PUBLIC_C", "SECRET_D", "SECRET_E"):
        row = f"{name:<12}"
        for mode in ("safe", "unsafe"):
            for point in ("p1", "p2", "p3"):
                row += f"{all_counts[mode][point][name]:<13}"
        print(row)
    print("\nАртефакты: demo_output/ (см. README.md)")

    uid = int(os.getenv("HOST_UID", "0"))
    gid = int(os.getenv("HOST_GID", "0"))
    if uid and gid:
        chown_tree(OUT_DIR, uid, gid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
