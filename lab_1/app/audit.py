"""Журнал аудита: JSON-строки в файле с правами 0600.

В журнал не попадают пароли, ключи и содержимое записей — только
кто, что, над чем и с каким результатом.
"""
import json
import os
import time


class AuditLog:
    def __init__(self, path: str):
        self.path = path

    def record(self, actor: str, action: str, result: str, target: str = "-") -> None:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "actor": actor,
            "action": action,
            "target": target,
            "result": result,
        }
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def tail(self, n: int = 20) -> list[str]:
        try:
            with open(self.path, encoding="utf-8") as fh:
                return fh.read().splitlines()[-n:]
        except FileNotFoundError:
            return []
