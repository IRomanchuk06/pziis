"""Хранилище: JSON-файлы 0600 в каталоге 0700, атомарная запись."""
import json
import os

USERS_FILE = "users.json"
RECORDS_FILE = "records.json"
KDF_SALT_FILE = "kdf.salt"


class Storage:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        os.umask(0o077)
        os.chmod(data_dir, 0o700)

    def _path(self, name: str) -> str:
        return os.path.join(self.data_dir, name)

    def _write(self, name: str, data) -> None:
        path = self._path(name)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def _read(self, name: str, default):
        try:
            with open(self._path(name), encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return default

    def load_users(self) -> list:
        return self._read(USERS_FILE, [])

    def save_users(self, users: list) -> None:
        self._write(USERS_FILE, users)

    def load_records(self) -> list:
        return self._read(RECORDS_FILE, [])

    def save_records(self, records: list) -> None:
        self._write(RECORDS_FILE, records)

    def load_or_create_kdf_salt(self) -> bytes:
        path = self._path(KDF_SALT_FILE)
        try:
            with open(path, "rb") as fh:
                salt = fh.read()
            if len(salt) == 32:
                return salt
        except FileNotFoundError:
            pass
        salt = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(salt)
        return salt
