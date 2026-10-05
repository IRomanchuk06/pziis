"""Бизнес-логика: аутентификация, сессии, роли, записи, аудит.

Роли и права:
  guest — чтение/поиск только неконфиденциальных данных;
  user  — CRUD неконфиденциальных + создание/чтение/изменение СВОИХ конфиденциальных;
  admin — полный доступ к данным и управлению пользователями.
"""
import json
import os
import time
import uuid

from audit import AuditLog
import security
from sessions import SessionManager
from storage import Storage

ROLES = ("admin", "user", "guest")


class AuthError(Exception):
    """Неверные учётные данные."""


class AccessDenied(Exception):
    """Операция запрещена политикой разграничения доступа."""


class ValidationError(Exception):
    """Некорректные входные данные."""


class NotFound(Exception):
    """Объект не найден."""


def _check_login(login) -> None:
    if not isinstance(login, str) or not 3 <= len(login) <= 32 or not login.isalnum():
        raise ValidationError("логин: 3-32 символа, буквы и цифры")


def _check_password(password) -> None:
    if not isinstance(password, str) or len(password) < 8:
        raise ValidationError("пароль: минимум 8 символов")


def _check_text(value, name: str, limit: int) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= limit:
        raise ValidationError(f"{name}: непустая строка до {limit} символов")


class App:
    def __init__(self, data_dir: str, master_password: str, admin_password: str | None = None):
        _check_text(master_password, "мастер-пароль", 128)
        self.storage = Storage(data_dir)
        self.audit = AuditLog(os.path.join(data_dir, "audit.log"))
        self.key = security.derive_key(master_password, self.storage.load_or_create_kdf_salt())
        self.users = {u["login"]: u for u in self.storage.load_users()}
        self.records = {r["id"]: r for r in self.storage.load_records()}
        self.sessions = SessionManager()
        if not self.users:
            if admin_password is None:
                raise ValidationError("пустое хранилище: нужен admin_password для инициализации")
            self._add_user_internal("admin", admin_password, "admin")
            self.audit.record("system", "init", "allow", "bootstrap:admin")

    # ---------- служебные ----------

    def _save_users(self) -> None:
        self.storage.save_users(list(self.users.values()))

    def _save_records(self) -> None:
        self.storage.save_records(list(self.records.values()))

    def _add_user_internal(self, login: str, password: str, role: str) -> None:
        salt_b64, pwd_hash = security.hash_password(password)
        self.users[login] = {
            "login": login,
            "role": role,
            "pwd_salt": salt_b64,
            "pwd_hash": pwd_hash,
            "created_at": time.time(),
        }
        self._save_users()

    def _actor(self, token: str, action: str, target: str = "-") -> dict:
        session = self.sessions.get(token)
        if session is None or session.login not in self.users:
            self.audit.record("anonymous", action, "deny", target)
            raise AccessDenied("сессия отсутствует или истекла")
        return self.users[session.login]

    def _deny(self, actor_login: str, action: str, target: str, reason: str) -> None:
        self.audit.record(actor_login, action, "deny", target)
        raise AccessDenied(reason)

    @staticmethod
    def _can_read(user: dict, rec: dict) -> bool:
        if not rec["confidential"]:
            return True
        return user["role"] == "admin" or rec["owner"] == user["login"]

    @staticmethod
    def _can_write(user: dict, rec: dict) -> bool:
        if user["role"] == "admin":
            return True
        if user["role"] == "guest":
            return False
        return rec["owner"] == user["login"]

    def _view(self, rec: dict) -> dict:
        if rec["confidential"]:
            payload = json.loads(security.decrypt(self.key, rec["enc_payload"]))
            title, content = payload["title"], payload["content"]
        else:
            title, content = rec["title"], rec["content"]
        return {
            "id": rec["id"],
            "owner": rec["owner"],
            "confidential": rec["confidential"],
            "title": title,
            "content": content,
            "updated_at": rec["updated_at"],
        }

    # ---------- аутентификация ----------

    def login(self, login: str, password: str) -> str:
        user = self.users.get(login)
        if user is None or not security.verify_password(password, user["pwd_salt"], user["pwd_hash"]):
            self.audit.record(login or "anonymous", "login", "deny")
            raise AuthError("неверный логин или пароль")
        token = self.sessions.create(login).token
        self.audit.record(login, "login", "allow")
        return token

    def logout(self, token: str) -> bool:
        session = self.sessions.get(token)
        actor = session.login if session else "anonymous"
        dropped = self.sessions.drop(token)
        self.audit.record(actor, "logout", "allow" if dropped else "deny")
        return dropped

    # ---------- пользователи ----------

    def add_user(self, token: str, login: str, password: str, role: str) -> None:
        actor = self._actor(token, "add_user", login)
        if actor["role"] != "admin":
            self._deny(actor["login"], "add_user", login, "добавлять пользователей может только admin")
        _check_login(login)
        _check_password(password)
        if role not in ROLES:
            raise ValidationError(f"роль должна быть одной из: {', '.join(ROLES)}")
        if login in self.users:
            raise ValidationError("пользователь с таким логином уже существует")
        self._add_user_internal(login, password, role)
        self.audit.record(actor["login"], "add_user", "allow", login)

    def delete_user(self, token: str, login: str) -> None:
        actor = self._actor(token, "delete_user", login)
        if actor["role"] != "admin":
            self._deny(actor["login"], "delete_user", login, "удалять пользователей может только admin")
        if login not in self.users:
            raise NotFound("пользователь не найден")
        admins = [u for u in self.users.values() if u["role"] == "admin"]
        if self.users[login]["role"] == "admin" and len(admins) == 1:
            raise ValidationError("нельзя удалить последнего администратора")
        del self.users[login]
        self.sessions.drop_for_login(login)
        self._save_users()
        self.audit.record(actor["login"], "delete_user", "allow", login)

    # ---------- записи ----------

    def add_record(self, token: str, title: str, content: str, confidential: bool) -> dict:
        actor = self._actor(token, "record_create")
        if actor["role"] == "guest":
            self._deny(actor["login"], "record_create", "-", "гостю запрещено создавать данные")
        _check_text(title, "заголовок", 128)
        _check_text(content, "содержимое", 4096)
        now = time.time()
        rec = {
            "id": uuid.uuid4().hex[:12],
            "owner": actor["login"],
            "confidential": bool(confidential),
            "created_at": now,
            "updated_at": now,
        }
        if rec["confidential"]:
            payload = json.dumps({"title": title, "content": content}, ensure_ascii=False)
            rec["enc_payload"] = security.encrypt(self.key, payload)
        else:
            rec["title"], rec["content"] = title, content
        self.records[rec["id"]] = rec
        self._save_records()
        self.audit.record(actor["login"], "record_create", "allow", rec["id"])
        return self._view(rec)

    def _get_record(self, rec_id: str) -> dict:
        rec = self.records.get(rec_id)
        if rec is None:
            raise NotFound("запись не найдена")
        return rec

    def get_record(self, token: str, rec_id: str) -> dict:
        actor = self._actor(token, "record_read", rec_id)
        rec = self._get_record(rec_id)
        if not self._can_read(actor, rec):
            self._deny(actor["login"], "record_read", rec_id, "нет прав на чтение этой записи")
        self.audit.record(actor["login"], "record_read", "allow", rec_id)
        return self._view(rec)

    def edit_record(self, token: str, rec_id: str, title: str | None = None,
                    content: str | None = None) -> dict:
        actor = self._actor(token, "record_edit", rec_id)
        rec = self._get_record(rec_id)
        if not self._can_write(actor, rec):
            self._deny(actor["login"], "record_edit", rec_id, "нет прав на изменение этой записи")
        if title is not None:
            _check_text(title, "заголовок", 128)
        if content is not None:
            _check_text(content, "содержимое", 4096)
        if rec["confidential"]:
            payload = json.loads(security.decrypt(self.key, rec["enc_payload"]))
            if title is not None:
                payload["title"] = title
            if content is not None:
                payload["content"] = content
            rec["enc_payload"] = security.encrypt(
                self.key, json.dumps(payload, ensure_ascii=False)
            )
        else:
            if title is not None:
                rec["title"] = title
            if content is not None:
                rec["content"] = content
        rec["updated_at"] = time.time()
        self._save_records()
        self.audit.record(actor["login"], "record_edit", "allow", rec_id)
        return self._view(rec)

    def delete_record(self, token: str, rec_id: str) -> None:
        actor = self._actor(token, "record_delete", rec_id)
        rec = self._get_record(rec_id)
        if not self._can_write(actor, rec):
            self._deny(actor["login"], "record_delete", rec_id, "нет прав на удаление этой записи")
        del self.records[rec_id]
        self._save_records()
        self.audit.record(actor["login"], "record_delete", "allow", rec_id)

    def search_records(self, token: str, query: str = "") -> list[dict]:
        actor = self._actor(token, "record_search")
        query_lower = query.lower()
        found = []
        for rec in self.records.values():
            if not self._can_read(actor, rec):
                continue
            view = self._view(rec)
            haystack = f"{view['title']} {view['content']}".lower()
            if not query_lower or query_lower in haystack:
                found.append(view)
        self.audit.record(actor["login"], "record_search", "allow", f"found:{len(found)}")
        return found
