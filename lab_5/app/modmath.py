"""Собственные реализации модульной арифметики для ЛР5 «Управление ключами».

Содержит:
  - mod_pow  -- быстрое дискретное возведение в степень по модулю
                 (бинарный алгоритм "справа налево", square-and-multiply);
  - bsgs_log -- дискретное логарифмирование методом baby-step giant-step
                 (алгоритм Шэнкса);
  - factorize, multiplicative_order -- вспомогательные функции для
                 проверки параметров Диффи-Хеллмана;
  - is_probable_prime -- тест Миллера-Рабина (для проверки p).
"""

import math

# Набор оснований, дающий детерминированный тест Миллера-Рабина
# для всех n < 3.3*10^24 (для 32-разрядных чисел достаточно с запасом).
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_probable_prime(n: int) -> bool:
    """Тест Миллера-Рабина. Детерминирован для n < 3.3*10^24."""
    if n < 2:
        return False
    for p in _MR_BASES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _MR_BASES:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Быстрое дискретное возведение в степень: base^exponent mod modulus.

    Бинарный алгоритм "справа налево": показатель представляется в
    двоичном виде, на каждом шаге основание возводится в квадрат
    (base -> base^2), а при единичном бите результат домножается.
    Сложность: O(log2 exponent) модульных умножений -- для 32-разрядных
    чисел это не более 32 умножений и 32 возведения в квадрат.
    """
    if modulus <= 0:
        raise ValueError("модуль должен быть положительным")
    if exponent < 0:
        raise ValueError("отрицательная степень не поддерживается")
    if modulus == 1:
        return 0
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:               # текущий бит показателя == 1
            result = result * base % modulus
        base = base * base % modulus   # квадрат основания
        exponent >>= 1                 # переходим к следующему биту
    return result


def bsgs_log(alpha: int, y: int, p: int):
    """Дискретный логарифм: возвращает x >= 0 такое, что alpha^x = y (mod p).

    Метод baby-step giant-step (Д. Шэнкс):
        m = ceil(sqrt(p - 1)),  x = i*m + j,  0 <= j < m
        baby-steps: хэш-таблица {alpha^j: j} для j = 0..m-1
        giant-steps: проверяем gamma_i = y * (alpha^(-m))^i, i = 0..m
        если gamma_i найден в таблице, то y = alpha^(i*m + j)

    Требует p -- простое (для обращения alpha^-m по теореме Ферма).
    Сложность: O(sqrt(p)) по времени и O(sqrt(p)) по памяти.
    Для p = 134041249: m = 11578.
    """
    alpha %= p
    y %= p
    m = math.isqrt(p - 1) + 1          # m >= ceil(sqrt(p-1))

    # baby steps: таблица значений alpha^j
    baby = {}
    cur = 1
    for j in range(m):
        if cur not in baby:            # храним наименьшее j для значения
            baby[cur] = j
        cur = cur * alpha % p

    # alpha^(-m) mod p = (alpha^m)^(p-2) mod p  (p простое => теорема Ферма)
    alpha_inv_m = mod_pow(mod_pow(alpha, m, p), p - 2, p)

    # giant steps
    gamma = y
    for i in range(m + 1):
        j = baby.get(gamma)
        if j is not None:
            x = i * m + j
            if mod_pow(alpha, x, p) == y:   # контрольная проверка корректности
                return x
        gamma = gamma * alpha_inv_m % p
    return None                         # решение не найдено (y вне <alpha>)


def factorize(n: int) -> dict:
    """Разложение n на простые множители (тривиальным делением).

    Для n ~ 2^31 достаточно перебора до sqrt(n) ~ 46000 -- выполняется
    за миллисекунды. Возвращает {простое: степень}.
    """
    factors = {}
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def multiplicative_order(alpha: int, p: int, factors: dict) -> int:
    """Мультипликативный порядок alpha mod p по разложению p-1.

    order = p-1; для каждого простого q | p-1 уменьшаем order,
    пока alpha^(order/q) == 1.
    """
    order = p - 1
    for q in factors:
        while order % q == 0 and mod_pow(alpha, order // q, p) == 1:
            order //= q
    return order
