#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Лабораторная работа № 4. Простые дополнительные тесты качества ГПСЧ.

Реализованы три простых теста (для оценки собственного генератора из
таблицы 1 и сравнения с другими датчиками):

1. Частотный (монобитный) тест — доля единичных битов:
       s_obs = |S - n/2| / sqrt(n/4),  p = erfc(s_obs / sqrt(2)),
   где S — число единиц, n — число битов. Проверяет равномерность битов.

2. Тест пар байтов (chi2 по 65536 значениям пары, 65535 степеней свободы):
       chi2 = sum (n_ij - e)^2 / e,  e = (N-1)/65536,
   p = Q(65535/2, chi2/2). Проверяет независимость соседних байтов.

3. Тест максимальной серии единиц (longest run of ones, NIST SP 800-22,
   блоки M = 128 бит): поток делится на блоки по 128 бит, для каждого блока
   ищется длина максимальной серии единиц L и категоризируется по таблице
   NIST для M = 128: L<=4, L=5, L=6, L>=7. Статистика chi2 с 3 степенями
   свободы по вероятностям pi = [0.1174, 0.2430, 0.2496, 0.3900].

Использование: python3 tools/extra_tests.py FILE [FILE ...]
"""

import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from expert import igamc, fmt_p  # noqa: E402


def test_frequency(data: bytes):
    """Частотный (монобитный) тест."""
    n = len(data) * 8
    if n == 0:
        raise ValueError("empty file")
    ones = int.from_bytes(data, "big").bit_count()
    s_obs = abs(ones - n / 2.0) / math.sqrt(n / 4.0)
    p = math.erfc(s_obs / math.sqrt(2.0))
    return ones, n, p


def test_byte_pairs(data: bytes):
    """Хи-квадрат по парам соседних байтов (65536 ячеек)."""
    if len(data) < 2:
        raise ValueError("file too small")
    counts = {}
    prev = data[0]
    for b in data[1:]:
        key = (prev << 8) | b
        counts[key] = counts.get(key, 0) + 1
        prev = b
    n = len(data) - 1
    e = n / 65536.0
    chi2 = 0.0
    for c in counts.values():
        d = c - e
        chi2 += d * d / e
    # ячейки с нулевым счётом дают (0-e)^2/e тоже
    chi2 += (65536 - len(counts)) * e
    p = igamc(65535 / 2.0, chi2 / 2.0)
    return chi2, p


_PI128 = (0.1174, 0.2430, 0.2496, 0.3900)  # NIST SP 800-22, M = 128


def test_longest_run(data: bytes):
    """Longest run of ones в блоке из 128 бит (NIST SP 800-22, M = 128)."""
    n_bits = len(data) * 8
    num_blocks = n_bits // 128
    if num_blocks < 49:
        raise ValueError("file too small for longest-run test")
    v = [0, 0, 0, 0]
    for i in range(num_blocks):
        block = data[i * 16:(i + 1) * 16]
        s = bin(int.from_bytes(block, "big"))[2:].zfill(128)
        runs = s.split("0")
        longest = max(len(r) for r in runs)
        if longest <= 4:        # категории NIST для M = 128
            v[0] += 1
        elif longest == 5:
            v[1] += 1
        elif longest == 6:
            v[2] += 1
        else:
            v[3] += 1
    chi2 = 0.0
    for vi, pi in zip(v, _PI128):
        np_ = num_blocks * pi
        chi2 += (vi - np_) ** 2 / np_
    p = igamc(1.5, chi2 / 2.0)  # df = 3
    return chi2, p


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    for path in argv[1:]:
        print("Файл: %s" % os.path.basename(path))
        try:
            with open(path, "rb") as f:
                data = f.read()
            ones, n, pf = test_frequency(data)
            print("  [1] Частотный тест:          единиц %d / %d бит (%.4f%%), "
                  "p = %s -> %s"
                  % (ones, n, 100.0 * ones / n, fmt_p(pf),
                     "пройден" if 0.01 < pf < 0.99 else "ПРОВАЛ"))
            chi2p, pp = test_byte_pairs(data)
            print("  [2] Тест пар байтов (65536): chi2 = %.2f, p = %s -> %s"
                  % (chi2p, fmt_p(pp),
                     "пройден" if 0.01 < pp < 0.99 else "ПРОВАЛ"))
            chi2r, pr = test_longest_run(data)
            print("  [3] Longest run (M=128):     chi2 = %.2f, p = %s -> %s"
                  % (chi2r, fmt_p(pr),
                     "пройден" if 0.01 < pr < 0.99 else "ПРОВАЛ"))
        except (OSError, ValueError) as exc:
            print("  ОШИБКА: %s" % exc)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
