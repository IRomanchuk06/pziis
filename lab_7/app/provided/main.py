"""CLI «предоставленного алгоритма» (ЛР7). Стиль намеренно иной, чем в own/.

Протокол команд совпадает с own/ (help/add/get/update/delete/list/stats/
dumpcore/noop/quit, строки [ok]/...) -- это нужно драйверу оценки. Штатный
поток операций работает; невалидные данные не обрабатываются (падения --
часть результатов оценки).
"""

import logging
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import store  # noqa: E402

PROMPT = "prv> "

HELP = """
commands:
  add secret|public|password <id>
  get <id>
  verify <id>
  update <id>
  delete <id>
  list
  stats
  dumpcore <path>
  quit
"""


def setup_logging():
    path = os.getenv("PROVIDED_LOG", "provided.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr), logging.FileHandler(path)],
    )


def gcore(path):
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    r = subprocess.run(
        ["gdb", "-p", str(os.getpid()), "-batch", "-ex", "gcore %s" % path],
        capture_output=True, text=True, timeout=180,
    )
    open(path + ".gdb.log", "w").write(r.stdout or "")
    open(path + ".gdb.log", "a").write(r.stderr or "")
    lines = [l for l in (r.stdout or "").splitlines() if l.strip() and "New" not in l and "Thread" not in l]
    for l in lines[-2:]:
        print("[dumpcore] %s" % l)
    print("[ok] dumpcore rc=%d path=%s" % (r.returncode, path))


def read_status():
    vm_rss = None
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                vm_rss = int(line.split()[1])
    return vm_rss


def main():
    setup_logging()
    print("[banner] реализация=provided python=%s pid=%d log=%s"
          % (sys.version.split()[0], os.getpid(), os.getenv("PROVIDED_LOG", "provided.log")))
    master = input("master pwd: ")
    store.init_crypto(master)
    while True:
        try:
            line = input(PROMPT)
        except EOFError:
            break
        parts = line.strip().split()
        if not parts:
            continue
        cmd = parts[0].lower()
        if cmd in ("quit", "exit"):
            break
        if cmd == "noop":
            print("[ok] noop")
            continue
        if cmd == "help":
            for l in HELP.strip().splitlines():
                print("[h] %s" % l)
            print("[ok] help")
            continue
        if cmd == "dumpcore":
            gcore(parts[1])
            continue
        if cmd == "add":
            kind, rid = parts[1], parts[2]
            value = input("value: ")
            store.put(kind, rid, value)
            print("[ok] put id=%s" % rid)
            continue
        if cmd == "get":
            kind, value = store.get(parts[1])
            print("[val] %s" % value)
            print("[ok] get id=%s" % parts[1])
            continue
        if cmd == "verify":
            cand = input("password: ")
            ok = store.verify_password(parts[1], cand)
            print("[ok] verify id=%s -> %s" % (parts[1], "MATCH" if ok else "MISMATCH"))
            continue
        if cmd == "update":
            value = input("new value: ")
            store.update(parts[1], value)
            print("[ok] update id=%s" % parts[1])
            continue
        if cmd == "delete":
            store.delete(parts[1])
            print("[ok] delete id=%s" % parts[1])
            continue
        if cmd == "list":
            for rid in store.ids():
                print("[rec] id=%s kind=%s" % (rid, store.kind_of(rid)))
            print("[ok] records: %d" % len(store.ids()))
            continue
        if cmd == "stats":
            st = store.stats_extra()
            print("[stats] vm_rss_kB=%s records=%s hist_len=%s" % (read_status(), st["records"], st["hist_len"]))
            print("[ok] stats")
            continue
        # ДЕФЕКТ: неизвестная команда -> необработанное исключение
        raise ValueError("unknown command: %r" % cmd)
    print("[ok] exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
