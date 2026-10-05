#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Лабораторная работа № 4. Сравнительная таблица всех протестированных файлов.

Строит markdown-таблицу: файл / размер / chi2 / p / вердикт программы «Expert».
Файл CryptGenRandom (crypt_out.bin) включается, только если он реально
существует (создан под wine; иначе запуск требует Windows).

Использование: python3 tools/make_table.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from expert import analyze_file, fmt_p  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "demo_output")

CANDIDATES = [
    ("demo_output/data/msvc_rand.bin", "Датчик rand() как в MS VS (младшие байты, 20 МБ)"),
    ("demo_output/data/own_gen.bin", "Свой генератор — формула (1) табл. 1 (12 МБ)"),
    ("demo_output/data/crypt_out.bin", "CryptGenRandom (CryptoAPI), запуск под wine в docker"),
    ("demo_output/data/urandom.bin", "/dev/urandom (эталон, 1 МБ)"),
    ("bin/gen_own", "Программный код: ELF-бинарник gen_own (g++)"),
    ("bin/gen_crypt.exe", "Программный код: PE-.exe gen_crypt (MinGW)"),
    ("demo_output/data/archive.zip", "Архив .zip с исходниками проекта"),
]


def main():
    print("# Сравнительная таблица (программа «Expert», хи-квадрат, 256 ст. св.)")
    print()
    print("| Файл | Описание | Размер, Б | chi2 | p | Вердикт |")
    print("|---|---|---:|---:|---:|---|")
    for rel, desc in CANDIDATES:
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        r = analyze_file(path)
        print("| %s | %s | %d | %.2f | %s | %s |"
              % (os.path.basename(rel), desc, r["size"], r["chi2"],
                 fmt_p(r["p"]), r["verdict"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
