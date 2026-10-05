"""Нагрузочный тест одной реализации (ЛР7, критерий C4 методики).

Запуск: ``python3 app/bench_impl.py <own|provided> <N>``
Печатает JSON: время/CPU/RSS по фазам add/update/delete для N секретных
записей. Выполняется отдельным процессом, чтобы замер RSS был изолирован.
"""

from __future__ import annotations

import json
import os
import sys
import time

APP_DIR = os.path.dirname(os.path.abspath(__file__))
N_DEFAULT = 2000


def read_rss_kB() -> int:
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("VmRSS not found")


def gen_value(prefix: str) -> str:
    return prefix + "-" + os.urandom(20).hex()


def make_backend(impl: str, master: str):
    if impl == "own":
        sys.path.insert(0, os.path.join(APP_DIR, "own"))
        import vault as own_vault  # noqa: PLC0415

        vault = own_vault.SafeVault(master)
        return (
            lambda rid, v: vault.add("secret", rid, v),
            lambda rid, v: vault.update(rid, v),
            lambda rid: vault.delete(rid),
            vault,
        )
    if impl == "provided":
        sys.path.insert(0, os.path.join(APP_DIR, "provided"))
        import store as provided_store  # noqa: PLC0415

        provided_store.init_crypto(master)
        return (
            lambda rid, v: provided_store.put("secret", rid, v),
            lambda rid, v: provided_store.update(rid, v),
            lambda rid: provided_store.delete(rid),
            provided_store,
        )
    raise SystemExit(f"unknown impl: {impl}")


def run_phase(name: str, n: int, fn) -> dict:
    rss_before = read_rss_kB()
    cpu0, wall0 = time.process_time(), time.perf_counter()
    ok = 0
    error = None
    try:
        for i in range(n):
            fn(f"rec{i:05d}")
            ok += 1
    except Exception as exc:  # noqa: BLE001 -- фиксируем как результат фазы
        error = f"{type(exc).__name__}: {exc}"[:200]
    cpu1, wall1 = time.process_time(), time.perf_counter()
    rss_after = read_rss_kB()
    wall = wall1 - wall0
    return {
        "phase": name,
        "n": n,
        "ok": ok,
        "error": error,
        "wall_s": round(wall, 4),
        "cpu_s": round(cpu1 - cpu0, 4),
        "rss_before_kB": rss_before,
        "rss_after_kB": rss_after,
        "drss_kB": rss_after - rss_before,
        "rss_per_record_kB": round((rss_after - rss_before) / n, 4) if n else 0.0,
        "avg_ms": round(wall * 1000.0 / n, 4) if n else 0.0,
    }


def main() -> int:
    impl = sys.argv[1] if len(sys.argv) > 1 else "own"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else N_DEFAULT
    master = "load-master-" + os.urandom(8).hex()
    add_op, update_op, delete_op, backend = make_backend(impl, master)

    # подготовка значений: уникальные на фазу (update пишет новое значение)
    add_values = {f"rec{i:05d}": gen_value("CARD") for i in range(n)}
    upd_values = {f"rec{i:05d}": gen_value("CARD") for i in range(n)}

    result = {"impl": impl, "n": n, "phases": []}

    rss0 = read_rss_kB()
    cpu0, wall0 = time.process_time(), time.perf_counter()
    if impl == "own":
        # init: вывод ключа из мастер-пароля (PBKDF2) уже выполнен в SafeVault
        pass
    result["init"] = {
        "rss_kB": rss0,
        "wall_s": round(time.perf_counter() - wall0, 4),
    }

    phase = run_phase("add", n, lambda rid: add_op(rid, add_values[rid]))
    result["phases"].append(phase)
    phase = run_phase("update", n, lambda rid: update_op(rid, upd_values[rid]))
    result["phases"].append(phase)
    phase = run_phase("delete", n, delete_op)
    result["phases"].append(phase)

    result["success"] = all(p["ok"] == p["n"] for p in result["phases"])
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
