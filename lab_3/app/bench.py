"""Замеры оперативной памяти и процессорного времени (пункт 3 задания ЛР3).

Запускается внутри контейнера: ``python3 app/bench.py <out_dir>``.

Для каждого режима (safe/unsafe) выполняются одинаковые фазы операций и
фиксируются: VmRSS из /proc/self/status до и после фазы, дельта RSS,
процессорное время (time.process_time) и астрономическое время
(time.perf_counter). Результат: metrics.csv + metrics.md (сводная таблица).
"""

from __future__ import annotations

import csv
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from vault import (  # noqa: E402
    PBKDF2_ITERATIONS,
    SafeVault,
    UnsafeVault,
    derive_key,
    read_status_counters,
    scrub_free_memory,
)

N_SECRET = 400
N_PUBLIC = 200
VALUE_BYTES = 64  # значение секрета: 64 случайных байта -> 128 hex-символов


def gen_value(prefix: str, size: int = VALUE_BYTES) -> str:
    return prefix + "-" + os.urandom(size).hex()


class Phase:
    def __init__(self, mode: str, name: str, n: int) -> None:
        self.mode = mode
        self.name = name
        self.n = n
        self.before = read_status_counters()

    def finish(self, ok: int) -> dict:
        after = read_status_counters()
        return {
            "mode": self.mode,
            "phase": self.name,
            "n": self.n,
            "ok": ok,
            "rss_before_kB": self.before["vm_rss_kB"],
            "rss_after_kB": after["vm_rss_kB"],
            "drss_kB": (after["vm_rss_kB"] or 0) - (self.before["vm_rss_kB"] or 0),
            "cpu_s": round(after["cpu_s"] - self.before["cpu_s"], 4),
            "wall_s": round(after["wall_s"] - self.before["wall_s"], 4),
            "avg_ms": round(
                (after["wall_s"] - self.before["wall_s"]) * 1000.0 / self.n, 4
            )
            if self.n
            else 0.0,
        }


def bench_mode(mode: str) -> list[dict]:
    rows: list[dict] = []
    master = "bench-master-" + os.urandom(8).hex()
    phase = Phase(mode, "init: мастер-пароль -> ключ (PBKDF2/AESGCM)", 1)
    vault = SafeVault(master) if mode == "safe" else UnsafeVault(master)
    del master
    rows.append(phase.finish(1))

    # 1. добавление конфиденциальных записей
    phase = Phase(mode, f"add secret x{N_SECRET}", N_SECRET)
    ok = 0
    for i in range(N_SECRET):
        vault.add("secret", f"sec{i:04d}", gen_value("CARD"))
        ok += 1
    rows.append(phase.finish(ok))

    # 2. добавление неконфиденциальных записей
    phase = Phase(mode, f"add public x{N_PUBLIC}", N_PUBLIC)
    ok = 0
    for i in range(N_PUBLIC):
        vault.add("public", f"pub{i:04d}", gen_value("NOTE"))
        ok += 1
    rows.append(phase.finish(ok))

    # 3. обновление конфиденциальных записей
    phase = Phase(mode, f"update secret x{N_SECRET}", N_SECRET)
    ok = 0
    for i in range(N_SECRET):
        vault.update(f"sec{i:04d}", gen_value("CARD"))
        ok += 1
    rows.append(phase.finish(ok))

    # 4. чтение всех записей
    phase = Phase(mode, f"get all x{N_SECRET + N_PUBLIC}", N_SECRET + N_PUBLIC)
    ok = 0
    for i in range(N_SECRET):
        vault.get(f"sec{i:04d}")
        ok += 1
    for i in range(N_PUBLIC):
        vault.get(f"pub{i:04d}")
        ok += 1
    if mode == "safe":
        vault.scrub()
    rows.append(phase.finish(ok))

    # 5. удаление конфиденциальных записей
    phase = Phase(mode, f"delete secret x{N_SECRET}", N_SECRET)
    ok = 0
    for i in range(N_SECRET):
        vault.delete(f"sec{i:04d}")
        ok += 1
    rows.append(phase.finish(ok))

    # 6. удаление неконфиденциальных записей
    phase = Phase(mode, f"delete public x{N_PUBLIC}", N_PUBLIC)
    ok = 0
    for i in range(N_PUBLIC):
        vault.delete(f"pub{i:04d}")
        ok += 1
    rows.append(phase.finish(ok))

    vault.close()
    return rows


def bench_micro() -> list[dict]:
    """Микробенчмарки отдельных примитивов."""
    rows: list[dict] = []

    start = read_status_counters()
    salt = os.urandom(16)
    derive_key("bench-password-123", salt)
    after = read_status_counters()
    rows.append(
        {
            "mode": "micro",
            "phase": f"PBKDF2-HMAC-SHA256 x1 ({PBKDF2_ITERATIONS} итераций)",
            "n": 1,
            "ok": 1,
            "rss_before_kB": start["vm_rss_kB"],
            "rss_after_kB": after["vm_rss_kB"],
            "drss_kB": after["vm_rss_kB"] - start["vm_rss_kB"],
            "cpu_s": round(after["cpu_s"] - start["cpu_s"], 4),
            "wall_s": round(after["wall_s"] - start["wall_s"], 4),
            "avg_ms": round((after["wall_s"] - start["wall_s"]) * 1000.0, 4),
        }
    )

    key = os.urandom(32)
    aes = AESGCM(key)
    data = os.urandom(128)
    nonce = os.urandom(12)
    start = read_status_counters()
    for _ in range(1000):
        aes.encrypt(nonce, data, None)
    after = read_status_counters()
    rows.append(
        {
            "mode": "micro",
            "phase": "AES-256-GCM encrypt(128 Б) x1000",
            "n": 1000,
            "ok": 1000,
            "rss_before_kB": start["vm_rss_kB"],
            "rss_after_kB": after["vm_rss_kB"],
            "drss_kB": after["vm_rss_kB"] - start["vm_rss_kB"],
            "cpu_s": round(after["cpu_s"] - start["cpu_s"], 4),
            "wall_s": round(after["wall_s"] - start["wall_s"], 4),
            "avg_ms": round((after["wall_s"] - start["wall_s"]), 4),
        }
    )

    start = read_status_counters()
    scrub_free_memory()
    after = read_status_counters()
    rows.append(
        {
            "mode": "micro",
            "phase": "scrub_free_memory() x1",
            "n": 1,
            "ok": 1,
            "rss_before_kB": start["vm_rss_kB"],
            "rss_after_kB": after["vm_rss_kB"],
            "drss_kB": after["vm_rss_kB"] - start["vm_rss_kB"],
            "cpu_s": round(after["cpu_s"] - start["cpu_s"], 4),
            "wall_s": round(after["wall_s"] - start["wall_s"], 4),
            "avg_ms": round((after["wall_s"] - start["wall_s"]) * 1000.0, 4),
        }
    )
    return rows


CSV_FIELDS = [
    "mode", "phase", "n", "ok",
    "rss_before_kB", "rss_after_kB", "drss_kB",
    "cpu_s", "wall_s", "avg_ms",
]


def write_markdown(path: str, rows: list[dict]) -> None:
    lines = [
        "# Сводная таблица: ОЗУ и процессорное время (реальные замеры в контейнере)",
        "",
        "Условия: python:3.12-slim, docker, VmRSS из `/proc/self/status`,",
        "CPU -- `time.process_time()`, wall -- `time.perf_counter()`.",
        f"Объём: {N_SECRET} конфиденциальных записей (значение {VALUE_BYTES} байт =>",
        f"{VALUE_BYTES * 2} hex-символов) и {N_PUBLIC} неконфиденциальных.",
        "",
        "| Режим | Операция | N | RSS до, кБ | RSS после, кБ | ΔRSS, кБ | CPU, с | Wall, с | avg, мс/оп |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {mode} | {phase} | {n} | {rss_before_kB} | {rss_after_kB} | "
            "{drss_kB} | {cpu_s} | {wall_s} | {avg_ms} |".format(**row)
        )
    lines += [
        "",
        "Примечания (объясняются в отчёте):",
        "",
        "* ΔRSS после `delete` не возвращается к исходному значению ни в одном",
        "  режиме: аллокатор CPython (pymalloc) удерживает арены, а glibc --",
        "  кучу процесса; освобождение памяти ≠ её возврат ОС.",
        "* В safe-режиме каждая операция с секретом включает затирание буферов",
        "  и `scrub_free_memory()`; его стоимость видна в micro-строке.",
        "",
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main() -> int:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "demo_output"
    os.makedirs(out_dir, exist_ok=True)
    print(f"[bench] режимы: safe, unsafe; secret={N_SECRET}, public={N_PUBLIC}")

    rows: list[dict] = []
    for mode in ("safe", "unsafe"):
        t0 = time.perf_counter()
        rows += bench_mode(mode)
        print(f"[bench] режим {mode} завершён за {time.perf_counter() - t0:.1f} с")
    rows += bench_micro()

    csv_path = os.path.join(out_dir, "metrics.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    write_markdown(os.path.join(out_dir, "metrics.md"), rows)
    print(f"[bench] готово: {csv_path}, {os.path.join(out_dir, 'metrics.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
