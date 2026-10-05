#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Лабораторная работа 5. Управление ключами.

Демонстрация выполняется по шагам:
  1. Собственная реализация дискретного возведения в степень по модулю
     для 32-разрядных чисел + сравнение с встроенной pow(b, e, m).
  2. Алгоритм Диффи-Хеллмана для двух пользователей
     (p = 134041249, alpha = 7).
  3. Дискретное логарифмирование (baby-step giant-step) и восстановление X.
  4. Измерение и сравнение времени: возведение в степень vs логарифм.

Запуск: python3 main.py  (внутри контейнера, см. run.sh)
"""

import math
import platform
import random
import sys
import time

from modmath import (bsgs_log, factorize, is_probable_prime, mod_pow,
                     multiplicative_order)

P = 134041249      # простое число по условию (32-разрядное: 2^27 < p < 2^31)
ALPHA = 7          # генератор группы по условию
SEED = 2026        # фиксированное зерно ГПСЧ -- воспроизводимость демо
POW_PROBES = 1000  # случайных пар (b, e) в одном прогоне замера modexp
POW_RUNS = 20      # число прогонов замера для возведения в степень
BSGS_RUNS = 30     # число прогонов замера для BSGS

LINE = "=" * 70


def header(title: str) -> None:
    print(f"\n{LINE}\n{title}\n{LINE}")


def fmt_time(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1e6:10.2f} мкс"
    return f"{seconds * 1e3:10.3f} мс"


def avg_time(fn, *args, repeats: int = 1) -> float:
    """Среднее время выполнения fn(*args) по repeats запускам (perf_counter)."""
    t0 = time.perf_counter()
    for _ in range(repeats):
        fn(*args)
    return (time.perf_counter() - t0) / repeats


# ---------------------------------------------------------------- шаг 1 ---
def demo_mod_pow() -> None:
    header("ШАГ 1. ДИСКРЕТНОЕ ВОЗВЕДЕНИЕ В СТЕПЕНЬ ПО МОДУЛЮ (32-бит)")
    print("Алгоритм: бинарное быстрое возведение (square-and-multiply,")
    print("справа налево); сложность O(log2 e) модульных умножений.\n")

    samples = [
        (7, 123456, P),
        (123456789, 987654321, P),
        (2, 31, 2147483647),
        (3735928559 % P, 305419896, P),
    ]
    ok_all = True
    for b, e, m in samples:
        mine = mod_pow(b, e, m)
        builtin = pow(b, e, m)
        ok = (mine == builtin)
        ok_all &= ok
        print(f"  {b}^{e} mod {m}")
        print(f"    своя реализация mod_pow : {mine}")
        print(f"    встроенная pow(b,e,m)   : {builtin}")
        print(f"    совпадение результатов  : {'ДА' if ok else 'НЕТ'}")

    # Сравнение времени на 1000 случайных 32-разрядных пар (b, e)
    cases = [(random.randrange(2, P), random.randrange(2, P), P)
             for _ in range(POW_PROBES)]

    def run_all(fn, *_):
        for b, e, m in cases:
            fn(b, e, m)

    t_mine = avg_time(run_all, mod_pow, repeats=POW_RUNS) / POW_PROBES
    t_bltin = avg_time(run_all, pow, repeats=POW_RUNS) / POW_PROBES
    print(f"\n  Среднее время одной операции ({POW_PROBES} случайных пар (b, e, {P}), "
          f"{POW_RUNS} прогонов):")
    print(f"    своя реализация mod_pow : {fmt_time(t_mine)}")
    print(f"    встроенная pow          : {fmt_time(t_bltin)}")
    print(f"    отношение (своя/pow)    : {t_mine / t_bltin:.2f}x")
    print(f"\n  ИТОГ ШАГА 1: все контрольные значения совпали: "
          f"{'ДА' if ok_all else 'НЕТ'}")


# ---------------------------------------------------------------- шаг 2 ---
def demo_dh():
    header("ШАГ 2. АЛГОРИТМ ДИФФИ-ХЕЛЛМАНА (p = 134041249, alpha = 7)")

    facts = factorize(P - 1)
    print(f"  Проверка параметров: p простое (Миллер-Рабин): "
          f"{is_probable_prime(P)}")
    pretty = " * ".join(f"{q}^{k}" if k > 1 else f"{q}"
                        for q, k in sorted(facts.items()))
    print(f"  Разложение p-1 = {pretty}")
    order = multiplicative_order(ALPHA, P, facts)
    print(f"  Порядок alpha = {ALPHA} mod p: {order} "
          f"{'(alpha -- первообразный корень, образующая)' if order == P - 1 else ''}\n")

    # Секретные ключи -- случайные 32-разрядные числа, X < p
    x1 = random.randrange(2, P - 1)     # секрет Алисы
    x2 = random.randrange(2, P - 1)     # секрет Боба
    y1 = mod_pow(ALPHA, x1, P)          # открытый ключ Алисы
    y2 = mod_pow(ALPHA, x2, P)          # открытый ключ Боба
    s_b = mod_pow(y1, x2, P)            # Боб:  (Y1)^X2 mod p
    s_a = mod_pow(y2, x1, P)            # Алиса: (Y2)^X1 mod p

    print(f"  X1 (секретный ключ Алисы)  = {x1}")
    print(f"  X2 (секретный ключ Боба)   = {x2}")
    print(f"  Y1 = alpha^X1 mod p        = {y1}")
    print(f"  Y2 = alpha^X2 mod p        = {y2}")
    print(f"  Секрет Боба  (Y1)^X2 mod p = {s_b}")
    print(f"  Секрет Алисы (Y2)^X1 mod p = {s_a}")
    print(f"\n  Секреты совпадают: {'ДА' if s_a == s_b else 'НЕТ'}"
          f"  (общий ключ K = {s_a})")

    # Контроль встроенной функцией возведения в степень
    check = (pow(y1, x2, P) == pow(y2, x1, P) == s_a)
    print(f"  Контроль встроенной pow(b,e,m): {'ДА' if check else 'НЕТ'}")
    return x1, x2, y1, y2, s_a


# ---------------------------------------------------------------- шаг 3 ---
def demo_bsgs(x1, x2, y1, y2):
    header("ШАГ 3. ДИСКРЕТНОЕ ЛОГАРИФМИРОВАНИЕ (baby-step giant-step)")
    m = math.isqrt(P - 1) + 1
    print("  Дано: Y = alpha^X (mod p). Найти X.")
    print(f"  BSGS: m = ceil(sqrt(p-1)) = {m}; X = i*m + j;")
    print("  baby-steps: таблица alpha^j; giant-steps: y*(alpha^-m)^i;")
    print("  сложность O(sqrt(p)) по времени и памяти.\n")

    # 3.1 Контрольная задача на случайном X
    xr = random.randrange(2, P - 1)
    yr = mod_pow(ALPHA, xr, P)
    xf = bsgs_log(ALPHA, yr, P)
    ok = (xf == xr)
    print(f"  3.1 Контроль: Y = alpha^{xr} mod p = {yr}")
    print(f"      BSGS нашёл X = {xf}; истинный X = {xr}; "
          f"совпадение: {'ДА' if ok else 'НЕТ'}")

    # 3.2 "Атака" на Диффи-Хеллман: восстановление секретов по открытым Y
    print("\n  3.2 Восстановление секретных ключей ДХ по открытым Y1, Y2:")
    restored = {}
    for label, y, x_true in (("X1", y1, x1), ("X2", y2, x2)):
        x_found = bsgs_log(ALPHA, y, P)
        restored[label] = x_found
        good = (x_found == x_true)
        print(f"      Y{label[1]} = {y}")
        print(f"        найдено X = {x_found}; истинное {label} = {x_true}; "
              f"совпадение: {'ДА' if good else 'НЕТ'}")
    return ok and restored["X1"] == x1 and restored["X2"] == x2


# ---------------------------------------------------------------- шаг 4 ---
def demo_timing(y1: int) -> dict:
    header("ШАГ 4. СРАВНЕНИЕ ВРЕМЁН: ВОЗВЕДЕНИЕ В СТЕПЕНЬ vs ЛОГАРИФМ")
    cases = [(random.randrange(2, P), random.randrange(2, P), P)
             for _ in range(POW_PROBES)]

    def run_all(fn, *_):
        for b, e, m in cases:
            fn(b, e, m)

    t_mine = avg_time(run_all, mod_pow, repeats=POW_RUNS) / POW_PROBES
    t_bltin = avg_time(run_all, pow, repeats=POW_RUNS) / POW_PROBES
    t_bsgs = avg_time(bsgs_log, ALPHA, y1, P, repeats=BSGS_RUNS)

    print(f"  ({POW_RUNS} прогонов по {POW_PROBES} операций для modexp, "
          f"{BSGS_RUNS} прогонов для BSGS; time.perf_counter)\n")
    print(f"  {'Операция':<44}{'Среднее время':>16}{'Прогонов':>12}")
    print(f"  {'-' * 72}")
    print(f"  {'Возведение в степень (своя mod_pow)':<44}"
          f"{fmt_time(t_mine):>16}{POW_RUNS * POW_PROBES:>12}")
    print(f"  {'Возведение в степень (встроенная pow)':<44}"
          f"{fmt_time(t_bltin):>16}{POW_RUNS * POW_PROBES:>12}")
    print(f"  {'Дискретный логарифм (BSGS, p = 134041249)':<44}"
          f"{fmt_time(t_bsgs):>16}{BSGS_RUNS:>12}")
    print(f"\n  Отношение времени логарифмирования к возведению в степень:")
    print(f"    BSGS / mod_pow(своя) = {t_bsgs / t_mine:8.1f}x")
    print(f"    BSGS / pow(встроен.) = {t_bsgs / t_bltin:8.1f}x")
    return {"mod_pow": t_mine, "pow": t_bltin, "bsgs": t_bsgs}


# ---------------------------------------------------------------- main ---
def main() -> int:
    random.seed(SEED)
    print(LINE)
    print("ЛАБОРАТОРНАЯ РАБОТА 5. УПРАВЛЕНИЕ КЛЮЧАМИ")
    print(f"Python {sys.version.split()[0]} | {platform.platform()}")
    print(f"Параметры ДХ: p = {P}, alpha = {ALPHA}; seed ГПСЧ = {SEED}")
    print(LINE)

    demo_mod_pow()
    x1, x2, y1, y2, secret = demo_dh()
    bsgs_ok = demo_bsgs(x1, x2, y1, y2)
    times = demo_timing(y1)

    header("ИТОГОВАЯ СВОДКА")
    print(f"  X1 = {x1}, X2 = {x2}")
    print(f"  Y1 = {y1}, Y2 = {y2}")
    print(f"  Общий секрет K = {secret}")
    print(f"  Восстановленные BSGS ключи совпадают с исходными: "
          f"{'ДА' if bsgs_ok else 'НЕТ'}")
    print(f"  Времена: mod_pow(своя) = {fmt_time(times['mod_pow'])}, "
          f"pow(встр.) = {fmt_time(times['pow'])}, "
          f"BSGS = {fmt_time(times['bsgs'])}")
    print(f"\n  ВЫВОД: при p ~ 2^27 логарифм находит секретный ключ ДХ за")
    print(f"  миллисекунды => 32-разрядный p непригоден для реальной криптографии.")
    print(LINE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
