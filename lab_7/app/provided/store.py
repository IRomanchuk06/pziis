"""«Предоставленный алгоритм» (лабораторная работа 7).

Вторая реализация того же функционала, что и own/ (хранилище из ЛР3),
написанная в другом стиле и с типовыми дефектами защищённости:

  * конфиденциальные данные хранятся как обычные str (hex-строка «шифртекта»),
    мастер-пароль живёт в глобальной переменной всю сессию;
  * «шифрование» — XOR с ключом из weak PRNG (модуль random, без
    криптостойкого источника);
  * пароли — слабый хэш MD5 без соли;
  * конфиденциальные значения пишутся в лог (logging) в открытом виде;
  * затирание памяти отсутствует; журнал операций удерживает ссылки на
    значения, в том числе «удалённых» записей;
  * чтение через input() (буферизация с опережением);
  * обработка невалидных данных отсутствует (необработанные исключения).

Реализация полностью работоспособна на штатном потоке операций и
демонстрируется в контейнере.
"""

import hashlib
import logging
import os
import random

LOG = logging.getLogger("provided_app")

# --- глобальное состояние (стиль «как получилось») -------------------------

KEY = None          # ключ «шифрования» из weak PRNG
STORE = {}          # id -> (kind, hexstr/value/md5hex)
PWLOG = {}          # id -> md5 hex (дублирующий индекс паролей)
HIST = []           # журнал операций: хранит и «удалённые» значения
MASTER = None       # мастер-пароль на всю сессию


def init_crypto(master_password):
    """Инициализация «криптографии» сессии.

    ДЕФЕКТ: ключ из модуля random (Mersenne Twister) -- предсказуемый
    источник, а не os.urandom/secrets.
    """
    global KEY, MASTER
    MASTER = master_password
    KEY = bytes([random.getrandbits(8) for _ in range(32)])
    LOG.info("crypto init: master=%s key=%s", master_password, KEY.hex())
    return KEY


def xor_hex(value):
    """«Шифрование»: XOR с KEY + hex. ДЕФЕКТ: самодельный шифр без аутентификации."""
    raw = value.encode("utf-8")
    enc = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(raw))
    return enc.hex()


def unxor_hex(hexstr):
    raw = bytes.fromhex(hexstr)
    return bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(raw)).decode("utf-8")


def new_rev():
    """«Уникальный» номер ревизии из weak PRNG (для журнала)."""
    return int(random.random() * 10 ** 9)


def put(kind, rid, value):
    """Добавить запись. Валидации нет: всё сохраняется как есть."""
    if kind == "password":
        h = hashlib.md5(value.encode("utf-8")).hexdigest()  # ДЕФЕКТ: MD5 без соли
        PWLOG[rid] = h
        stored = h
    elif kind == "secret":
        stored = xor_hex(value)
    else:
        stored = value
    STORE[rid] = (kind, stored)
    # ДЕФЕКТ: конфиденциальное значение в открытом виде попадает в лог
    LOG.info("PUT rev=%s id=%s kind=%s value=%s", new_rev(), rid, kind, value)
    HIST.append(("put", rid, value))
    return stored


def get(rid):
    kind, stored = STORE[rid]  # KeyError при отсутствии -- не обрабатывается
    if kind == "secret":
        value = unxor_hex(stored)
    else:
        value = stored
    LOG.info("GET rev=%s id=%s -> %s", new_rev(), rid, value)
    return kind, value


def update(rid, new_value):
    kind, old = STORE[rid]
    HIST.append(("update-old", rid, old))
    put(kind, rid, new_value)


def delete(rid):
    kind, stored = STORE.pop(rid)  # KeyError при отсутствии
    HIST.append(("delete", rid, stored))  # ДЕФЕКТ: значение удерживается журналом
    LOG.info("DELETE rev=%s id=%s kind=%s", new_rev(), rid, kind)


def verify_password(rid, candidate):
    return hashlib.md5(candidate.encode("utf-8")).hexdigest() == PWLOG[rid]


def ids():
    return sorted(STORE)


def kind_of(rid):
    return STORE[rid][0]


def stats_extra():
    return {"records": len(STORE), "hist_len": len(HIST), "key_hex": KEY.hex() if KEY else None}
