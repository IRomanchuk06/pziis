#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Лабораторная работа № 4. Создание тестового архива .zip.

Упаковывает исходные файлы проекта (cpp/, tools/, Dockerfile, скрипты)
в zip-архив средствами модуля zipfile (стандартная библиотека Python).
Архив затем проверяется программой «Expert» (пункт 1 задания).

Использование: python3 tools/make_zip.py <выходной.zip>
"""

import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SOURCES = [
    "cpp/gen_msvc.cpp",
    "cpp/gen_own.cpp",
    "cpp/gen_crypt.cpp",
    "tools/expert.py",
    "tools/extra_tests.py",
    "tools/make_zip.py",
    "tools/make_table.py",
    "Dockerfile",
    "docker-compose.yml",
    "scripts/demo.sh",
]


def main(argv):
    out = argv[1] if len(argv) > 1 else os.path.join(ROOT, "demo_output", "data", "archive.zip")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    count = 0
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in SOURCES:
            full = os.path.join(ROOT, rel)
            if os.path.isfile(full):
                zf.write(full, arcname=rel)
                count += 1
    size = os.path.getsize(out)
    print("OK: %s (%d files, %d bytes)" % (out, count, size))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
