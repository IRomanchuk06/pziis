"""Ядро хранилища для лабораторной работы 3.

Две реализации одного и того же функционала:

* ``SafeVault``  -- безопасный режим: конфиденциальные данные шифруются
  AES-256-GCM (ключ выводится из мастер-пароля по PBKDF2-HMAC-SHA256),
  пароли хранятся только в виде PBKDF2-хэшей, всё секретное размещается
  в ``bytearray`` и затирается при обновлении/удалении; после операций с
  секретами выполняется ``scrub_free_memory()`` (перепезапись освобождённых
  блоков кучи).
* ``UnsafeVault`` -- небезопасный режим (для сравнения): значения хранятся
  обычными ``str``, мастер-пароль живёт в памяти всё время работы,
  «журнал операций» сохраняет ссылки на значения (в том числе «удалённых»),
  никакое затирание не выполняется.

Валидация входных данных у обоих режимов ОДИНАКОВАЯ, чтобы различие режимов
сводилось именно к обращению с памятью.
"""

from __future__ import annotations

import gc
import hmac
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Параметры криптографии
PBKDF2_ITERATIONS = 600_000  # рекомендация OWASP для PBKDF2-HMAC-SHA256
KEY_LEN = 32                 # AES-256
SALT_LEN = 16
NONCE_LEN = 12               # рекомендованный размер nonce для GCM

# Типы записей: secret/public/password. Конфиденциальные типы: secret, password.
KIND_SECRET = "secret"
KIND_PUBLIC = "public"
KIND_PASSWORD = "password"
VALID_KINDS = (KIND_SECRET, KIND_PUBLIC, KIND_PASSWORD)

# Ограничения входных данных
MAX_ID_LEN = 64
MAX_VALUE_LEN = 4096


class ValidationError(ValueError):
    """Невалидный ввод пользователя (не криптографическая ошибка)."""


def validate_kind(kind: str) -> None:
    if kind not in VALID_KINDS:
        raise ValidationError(
            f"неизвестный тип записи {kind!r}; допустимо: {', '.join(VALID_KINDS)}"
        )


def validate_id(rid: str) -> None:
    if not isinstance(rid, str) or not rid.strip():
        raise ValidationError("идентификатор записи не может быть пустым")
    if len(rid) > MAX_ID_LEN:
        raise ValidationError(f"идентификатор длиннее {MAX_ID_LEN} символов")
    if any(ch.isspace() for ch in rid):
        raise ValidationError("идентификатор не должен содержать пробельных символов")


def validate_value(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("значение не может быть пустым")
    if len(value) > MAX_VALUE_LEN:
        raise ValidationError(f"значение длиннее {MAX_VALUE_LEN} символов")


def erase_bytearray(buf: bytearray | None) -> None:
    """Затирание содержимого изменяемого буфера нулями перед освобождением.

    Применимо только к ``bytearray``: содержимое ``bytes``/``str`` в CPython
    изменить нельзя, такие объекты можно лишь освободить и перезаписать кучу
    (см. scrub_free_memory).
    """
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0
    buf.clear()


def scrub_free_memory(rounds: int = 2) -> None:
    """Best-effort затирание уже освобождённых блоков кучи.

    CPython не затирает освобождаемую память: блоки pymalloc/libc malloc
    сохраняют старые байты до повторного использования. Приём: выделяем
    обнулённые блоки всех характерных размеров (pymalloc <=512 Б, далее
    libc malloc до порога mmap), чтобы планировщик памяти переиспользовал
    освободившиеся блоки и перезаписал остатки секретов.
    """
    gc.collect()
    sizes = (
        16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
        768, 1024, 1536, 2048, 3072, 4096, 6144, 8192,
        12288, 16384, 24576, 32768, 49152, 65536,
    )
    for _ in range(rounds):
        blocks = [bytearray(size) for size in sizes]  # bytearray(n) заполнен нулями
        del blocks
    gc.collect()


def read_status_counters() -> dict:
    """Счётчики памяти/CPU текущего процесса: VmRSS/VmHWM из /proc/self/status."""
    vm_rss = None
    vm_hwm = None
    with open("/proc/self/status", encoding="ascii") as fh:
        for line in fh:
            if line.startswith("VmRSS:"):
                vm_rss = int(line.split()[1])
            elif line.startswith("VmHWM:"):
                vm_hwm = int(line.split()[1])
    return {
        "vm_rss_kB": vm_rss,
        "vm_hwm_kB": vm_hwm,
        "cpu_s": time.process_time(),
        "wall_s": time.perf_counter(),
    }


class SafeVault:
    """Хранилище с шифрованием конфиденциальных данных и затиранием памяти."""

    mode = "safe"

    def __init__(self, master_password: str) -> None:
        validate_value(master_password)
        salt = os.urandom(SALT_LEN)
        key = derive_key(master_password, salt)
        # AESGCM копирует ключ во внутреннее (Rust) представление; питоновская
        # bytes-копия станет мусором и будет перезаписана scrub-ом ниже.
        self._aesgcm = AESGCM(key)
        del key
        self._master_salt = bytearray(salt)
        del salt
        self._records: dict[str, dict] = {}
        scrub_free_memory()

    # -- вспомогательные операции -------------------------------------

    def _encrypt(self, plaintext: str) -> tuple[bytearray, bytearray]:
        data = plaintext.encode("utf-8")
        nonce = os.urandom(NONCE_LEN)
        ciphertext = self._aesgcm.encrypt(nonce, data, None)
        del data
        return bytearray(nonce), bytearray(ciphertext)

    def _password_hash(self, value: str, salt: bytes) -> bytes:
        return derive_key(value, salt)

    def _get_record(self, rid: str) -> dict:
        try:
            return self._records[rid]
        except KeyError:
            raise ValidationError(f"запись {rid!r} не найдена") from None

    # -- CRUD ----------------------------------------------------------

    def add(self, kind: str, rid: str, value: str) -> None:
        validate_kind(kind)
        validate_id(rid)
        validate_value(value)
        if rid in self._records:
            raise ValidationError(f"запись {rid!r} уже существует")
        if kind == KIND_SECRET:
            nonce, ciphertext = self._encrypt(value)
            self._records[rid] = {"kind": kind, "nonce": nonce, "data": ciphertext}
        elif kind == KIND_PASSWORD:
            salt = os.urandom(SALT_LEN)
            digest = self._password_hash(value, salt)
            self._records[rid] = {
                "kind": kind,
                "salt": bytearray(salt),
                "hash": bytearray(digest),
            }
            del digest
        else:  # KIND_PUBLIC: неконфиденциальные данные хранятся как есть
            self._records[rid] = {"kind": kind, "value": value}
        scrub_free_memory()

    def get(self, rid: str) -> tuple[str, str | None]:
        """Возвращает (тип, значение). Для password значение неизвлекаемо."""
        rec = self._get_record(rid)
        kind = rec["kind"]
        if kind == KIND_SECRET:
            plaintext = self._aesgcm.decrypt(bytes(rec["nonce"]), bytes(rec["data"]), None)
            value = plaintext.decode("utf-8")
            del plaintext
            return kind, value
        if kind == KIND_PASSWORD:
            return kind, None
        return kind, rec["value"]

    def update(self, rid: str, new_value: str) -> None:
        validate_value(new_value)
        rec = self._get_record(rid)
        kind = rec["kind"]
        if kind == KIND_SECRET:
            nonce, ciphertext = self._encrypt(new_value)
            erase_bytearray(rec["nonce"])
            erase_bytearray(rec["data"])
            rec["nonce"] = nonce
            rec["data"] = ciphertext
        elif kind == KIND_PASSWORD:
            salt = os.urandom(SALT_LEN)
            digest = self._password_hash(new_value, salt)
            erase_bytearray(rec["salt"])
            erase_bytearray(rec["hash"])
            rec["salt"] = bytearray(salt)
            rec["hash"] = bytearray(digest)
            del digest
        else:
            rec["value"] = new_value
        scrub_free_memory()

    def delete(self, rid: str) -> None:
        rec = self._get_record(rid)
        del self._records[rid]
        for field in ("nonce", "data", "salt", "hash"):
            if field in rec:
                erase_bytearray(rec[field])
        rec.clear()
        del rec
        scrub_free_memory()

    def verify_password(self, rid: str, candidate: str) -> bool:
        rec = self._get_record(rid)
        if rec["kind"] != KIND_PASSWORD:
            raise ValidationError(f"запись {rid!r} не является паролем")
        validate_value(candidate)
        digest = self._password_hash(candidate, bytes(rec["salt"]))
        ok = hmac.compare_digest(bytes(rec["hash"]), digest)
        del digest
        scrub_free_memory()
        return ok

    def ids(self) -> list[str]:
        return sorted(self._records)

    def kind_of(self, rid: str) -> str:
        return self._get_record(rid)["kind"]

    def close(self) -> None:
        for rec in self._records.values():
            for field in ("nonce", "data", "salt", "hash"):
                if field in rec:
                    erase_bytearray(rec[field])
            rec.clear()
        self._records.clear()
        self._aesgcm = None  # Rust-копия ключа освободится, затереть её напрямую нельзя
        scrub_free_memory()

    def scrub(self) -> None:
        scrub_free_memory()


class UnsafeVault:
    """Небезопасный режим: те же операции, но секреты -- обычные ``str``.

    Отличия от SafeVault (иначе функционал идентичен):
      * значения хранятся в открытом виде как ``str``;
      * мастер-пароль сохраняется на всё время работы;
      * «журнал операций» хранит ссылки на значения, в том числе удалённых
        записей (типовая ошибка реальных приложений);
      * затирание памяти не выполняется вовсе.
    """

    mode = "unsafe"

    def __init__(self, master_password: str) -> None:
        validate_value(master_password)
        self._master_password = master_password
        self._records: dict[str, dict] = {}
        self._history: list[tuple[str, str, str]] = []

    def _get_record(self, rid: str) -> dict:
        try:
            return self._records[rid]
        except KeyError:
            raise ValidationError(f"запись {rid!r} не найдена") from None

    def add(self, kind: str, rid: str, value: str) -> None:
        validate_kind(kind)
        validate_id(rid)
        validate_value(value)
        if rid in self._records:
            raise ValidationError(f"запись {rid!r} уже существует")
        self._records[rid] = {"kind": kind, "value": value}
        self._history.append(("add", rid, value))

    def get(self, rid: str) -> tuple[str, str | None]:
        rec = self._get_record(rid)
        return rec["kind"], rec["value"]

    def update(self, rid: str, new_value: str) -> None:
        validate_value(new_value)
        rec = self._get_record(rid)
        self._history.append(("update", rid, rec["value"]))
        rec["value"] = new_value
        self._history.append(("update-new", rid, new_value))

    def delete(self, rid: str) -> None:
        rec = self._get_record(rid)
        self._history.append(("delete", rid, rec["value"]))
        del self._records[rid]  # ссылка из history продолжает держать значение

    def verify_password(self, rid: str, candidate: str) -> bool:
        rec = self._get_record(rid)
        if rec["kind"] != KIND_PASSWORD:
            raise ValidationError(f"запись {rid!r} не является паролем")
        validate_value(candidate)
        return rec["value"] == candidate

    def ids(self) -> list[str]:
        return sorted(self._records)

    def kind_of(self, rid: str) -> str:
        return self._get_record(rid)["kind"]

    def close(self) -> None:
        pass  # никакой очистки памяти

    def scrub(self) -> None:
        pass  # затирание не предусмотрено


def derive_key(secret: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256: вывод ключа из секрета (мастер-пароль/пароль)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(secret.encode("utf-8"))


def make_vault(mode: str, master_password: str):
    if mode == SafeVault.mode:
        return SafeVault(master_password)
    if mode == UnsafeVault.mode:
        return UnsafeVault(master_password)
    raise ValidationError(f"неизвестный режим {mode!r}; допустимо: safe, unsafe")
