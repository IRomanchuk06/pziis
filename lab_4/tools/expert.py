#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Лабораторная работа № 4. Программа «Expert».

Реализует проверку заданного файла на случайность в соответствии с
критерием «Хи-квадрат» для 256 степеней свободы (как в программе
Expert.exe из методички).

Файл рассматривается как последовательность байтов. Пусть N — число байтов,
n_i — число вхождений байтового значения i (i = 0..255). Ожидаемое число
вхождений каждого значения при равномерном распределении: e = N / 256.

    chi2 = sum_{i=0}^{255} (n_i - e)^2 / e

Статистика имеет распределение хи-квадрат с k = 256 степенями свободы.
p-значение: p = Q(k/2, chi2/2) = Γ(k/2, chi2/2) / Γ(k/2) — регулярная
верхняя неполная гамма-функция (реализована на чистом math: ряд +
цепная дробь, алгоритм из Numerical Recipes). scipy не требуется.

Вердикты — как в методичке:
    «Последовательность не является случайной»
    «Последовательность подозрительна»
    «Последовательность почти подозрительна»
    (и четвёртый исход: тест пройден — последовательность признана случайной)

Числовые пороги в методичке не заданы, поэтому использованы стандартные
двусторонние уровни значимости: chi2 критически МАЛ (p > 0.99 — распределение
"слишком равномерное") либо критически ВЕЛИК (p < 0.01):
    p <= 0.01 или p >= 0.99 -> «не является случайной»
    p <= 0.05 или p >= 0.95 -> «подозрительна»
    p <= 0.10 или p >= 0.90 -> «почти подозрительна»
    иначе                   -> случайна (тест пройден)

Использование: python3 tools/expert.py FILE [FILE ...]
"""

import math
import os
import sys

K = 256  # число байтовых значений = число степеней свободы


def igamc(a: float, x: float) -> float:
    """Регулярная верхняя неполная гамма-функция Q(a, x) = Γ(a, x) / Γ(a).

    Чистый math: для x < a+1 — ряд для P(a, x), иначе — цепная дробь
    (модифицированный алгоритм Лента). Numerical Recipes, igamc/serior.
    """
    if x <= 0.0:
        return 1.0
    if a <= 0.0:
        raise ValueError("a must be positive")
    ln_prefactor = -x + a * math.log(x) - math.lgamma(a)
    if x < a + 1.0:
        # ряд для P(a, x)
        ap = a
        summ = 1.0 / a
        delt = summ
        for _ in range(100000):
            ap += 1.0
            delt *= x / ap
            summ += delt
            if abs(delt) < abs(summ) * 1e-17:
                break
        p = summ * math.exp(ln_prefactor)
        if p > 1.0:
            p = 1.0
        return 1.0 - p
    # цепная дробь для Q(a, x)
    b = x + 1.0 - a
    c = 1e300
    d = 1.0 / b
    h = d
    for i in range(1, 100000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < 1e-300:
            d = 1e-300
        c = b + an / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delt = d * c
        h *= delt
        if abs(delt - 1.0) < 1e-16:
            break
    return h * math.exp(ln_prefactor)


def byte_counts(data: bytes):
    """Частоты 256 байтовых значений (используется быстрый bytes.count)."""
    return [data.count(bytes([v])) for v in range(K)]


def chi_square(data: bytes):
    """Возвращает (chi2, p, n) для байтового представления файла."""
    n = len(data)
    if n == 0:
        raise ValueError("empty file")
    counts = byte_counts(data)
    e = n / K
    chi2 = sum((c - e) ** 2 for c in counts) / e
    p = igamc(K / 2.0, chi2 / 2.0)  # Q(128, chi2/2)
    return chi2, p, n


def verdict(p: float) -> str:
    """Вердикт по p-значению — формулировки как в методичке."""
    if p <= 0.01 or p >= 0.99:
        return "Последовательность не является случайной"
    if p <= 0.05 or p >= 0.95:
        return "Последовательность подозрительна"
    if p <= 0.10 or p >= 0.90:
        return "Последовательность почти подозрительна"
    return "Последовательность случайна (тест пройден)"


def analyze_file(path: str):
    with open(path, "rb") as f:
        data = f.read()
    chi2, p, n = chi_square(data)
    return {
        "name": path,
        "size": n,
        "chi2": chi2,
        "p": p,
        "verdict": verdict(p),
    }


def fmt_p(p: float) -> str:
    if p <= 0.0:
        return "<1e-300"
    if p > 0.999999999999:
        return "1-%.3g" % max(1.0 - p, 1e-16)
    return "%.6g" % p


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    files = argv[1:]
    print("Программа «Expert»: критерий хи-квадрат, %d степеней свободы" % K)
    print("chi2 = sum (n_i - N/256)^2 / (N/256);  p = Q(128, chi2/2)\n")
    header = "%-40s %12s %14s %14s  %s" % ("Файл", "Размер,Б", "chi2", "p", "Вердикт")
    print(header)
    print("-" * len(header))
    for path in files:
        try:
            r = analyze_file(path)
        except (OSError, ValueError) as exc:
            print("%-40s ОШИБКА: %s" % (path, exc))
            continue
        print("%-40s %12d %14.2f %14s  %s"
              % (os.path.basename(path), r["size"], r["chi2"],
                 fmt_p(r["p"]), r["verdict"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
