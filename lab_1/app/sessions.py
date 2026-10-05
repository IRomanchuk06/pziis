"""Сессии авторизации с тайм-аутом."""
import secrets
import time


class Session:
    __slots__ = ("token", "login", "expires_at")

    def __init__(self, token: str, login: str, ttl: int):
        self.token = token
        self.login = login
        self.expires_at = time.time() + ttl


class SessionManager:
    DEFAULT_TTL = 1800  # секунд

    def __init__(self, ttl: int = DEFAULT_TTL):
        self.ttl = ttl
        self._sessions: dict[str, Session] = {}

    def create(self, login: str, ttl: int | None = None) -> Session:
        session = Session(secrets.token_urlsafe(32), login, self.ttl if ttl is None else ttl)
        self._sessions[session.token] = session
        return session

    def get(self, token: str) -> Session | None:
        """Возвращает сессию либо None, если токен неизвестен или истёк."""
        session = self._sessions.get(token)
        if session is None:
            return None
        if time.time() >= session.expires_at:
            del self._sessions[token]
            return None
        return session

    def drop(self, token: str) -> bool:
        return self._sessions.pop(token, None) is not None

    def drop_for_login(self, login: str) -> None:
        for token in [t for t, s in self._sessions.items() if s.login == login]:
            del self._sessions[token]
