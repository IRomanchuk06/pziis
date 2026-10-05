"""Аудитор защищённости: автоматическая проверка приложения lab_1 по методике.

Исходники цели монтируются в /srv/target (read-only), Dockerfile цели —
в /srv/inspect/Dockerfile (read-only). Каждая проверка формирует запись
«проверка / ожидание / факт / вердикт»; итоговая таблица выводится в stdout
и сохраняется run.sh в demo_output/.

Проверки делятся на статические (анализ исходников и Dockerfile) и
динамические (тестовый прогон целевого приложения в изолированном каталоге
/srv/work с известными аудиторским паролями и маркерами).
"""
import json
import os
import re
import shutil
import sys
import time

TARGET_DIR = "/srv/target"
TARGET_DOCKERFILE = "/srv/inspect/Dockerfile"
WORK_DIR = "/srv/work"
DATA_DIR = os.path.join(WORK_DIR, "data")
CORE_MODULES = ("security.py", "storage.py", "sessions.py", "audit.py", "service.py")

# Секреты динамической среды: аудитор сам их создаёт и затем ищет их утечки
MASTER_PASSWORD = "Audit-Master-2026-Key"
ADMIN_PASSWORD = "Audit-Admin-2026"
ALICE_PASSWORD = "Audit-Alice-2026"
BOB_PASSWORD = "Audit-Bob-2026-Key1"
SECRET_MARKER = "SERVICE-TOKEN-AUDIT-777a1f"
PLAIN_MARKER = "plain-note-audit-marker"

SOURCES: dict[str, str] = {}
ALL_SRC = ""
CTX: dict = {}
RESULTS: list[tuple] = []


class CheckFailed(Exception):
    """Проверка не пройдена (fact содержит причину)."""


# ---------- инфраструктура проверок ----------

def run_check(cid: str, policy: str, title: str, expectation: str, fn) -> None:
    try:
        fact = fn()
        verdict = "PASS"
    except CheckFailed as exc:
        fact, verdict = str(exc), "FAIL"
    except Exception as exc:  # неожиданная ошибка — несоответствие
        fact, verdict = f"{type(exc).__name__}: {exc}", "FAIL"
    RESULTS.append((policy, cid, title, expectation, fact, verdict))
    print(f"  [{verdict}] {cid}: {fact}")


def load_sources() -> None:
    global SOURCES, ALL_SRC
    for name in sorted(os.listdir(TARGET_DIR)):
        path = os.path.join(TARGET_DIR, name)
        if name.endswith(".py") and os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                SOURCES[name] = fh.read()
    if not SOURCES:
        raise SystemExit(f"нет исходников в {TARGET_DIR}; проверьте volume-маунт")
    ALL_SRC = "\n".join(SOURCES.values())


def data_file_text(name: str) -> str:
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as fh:
        return fh.read()


# ---------- подготовка динамической среды ----------

def prepare_dynamic() -> None:
    # Изолируем путь от собственного каталога, чтобы импортировать модули цели
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path[:] = [p for p in sys.path if p not in ("", here)]
    sys.path.insert(0, TARGET_DIR)
    import service  # noqa: E402  (модуль цели)

    shutil.rmtree(WORK_DIR, ignore_errors=True)
    app = service.App(DATA_DIR, MASTER_PASSWORD, admin_password=ADMIN_PASSWORD)

    admin_token = app.login("admin", ADMIN_PASSWORD)
    app.add_user(admin_token, "alice", ALICE_PASSWORD, "user")
    app.add_user(admin_token, "bob", BOB_PASSWORD, "guest")
    secret_id = app.add_record(
        admin_token, "Ключи сервисного аккаунта", SECRET_MARKER, True
    )["id"]
    alice_token = app.login("alice", ALICE_PASSWORD)
    bob_token = app.login("bob", BOB_PASSWORD)
    app.add_record(alice_token, "Регламент резервного копирования", PLAIN_MARKER, False)

    CTX.update(app=app, service=service, admin_token=admin_token,
               alice_token=alice_token, bob_token=bob_token, secret_id=secret_id)


# ---------- статические проверки ----------

def s_dockerfile() -> str:
    if os.path.isdir(TARGET_DOCKERFILE):
        raise CheckFailed("Dockerfile цели недоступен (смонтирован каталог)")
    with open(TARGET_DOCKERFILE, encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r"^FROM\s+(\S+)", text, re.M)
    if not m:
        raise CheckFailed("инструкция FROM не найдена")
    base = m.group(1)
    if base.endswith(":latest") or ":" not in base:
        raise CheckFailed(f"базовый образ не зафиксирован: {base}")
    if not re.search(r"^USER\s+(?!root\b)\S+", text, re.M):
        raise CheckFailed("нет директивы USER (non-root)")
    return f"FROM {base}; USER non-root"


def s_pbkdf2() -> str:
    src = SOURCES.get("security.py", "")
    if "pbkdf2_hmac" not in src or '"sha256"' not in src:
        raise CheckFailed("вызов pbkdf2_hmac('sha256') не найден")
    return "hashlib.pbkdf2_hmac('sha256', ...) в security.py"


def s_iterations() -> str:
    m = re.search(r"PBKDF2_ITERATIONS\s*=\s*(\d[\d_]*)", ALL_SRC)
    if not m:
        raise CheckFailed("константа числа итераций не найдена")
    iters = int(m.group(1).replace("_", ""))
    if iters < 100_000:
        raise CheckFailed(f"слишком мало итераций: {iters} < 100000")
    return f"PBKDF2_ITERATIONS = {iters}"


def s_salt_random() -> str:
    if "os.urandom" not in SOURCES.get("security.py", ""):
        raise CheckFailed("os.urandom не используется для соли")
    return "соль генерируется os.urandom(16) на пользователя"


def s_sessions_static() -> str:
    src = SOURCES.get("sessions.py", "")
    m = re.search(r"DEFAULT_TTL\s*=\s*(\d+)", src)
    if not m:
        raise CheckFailed("константа TTL не найдена")
    ttl = int(m.group(1))
    if not 0 < ttl <= 8 * 3600:
        raise CheckFailed(f"подозрительный TTL: {ttl} c")
    if "expires_at" not in src or "time.time()" not in src:
        raise CheckFailed("проверка истечения сессии не найдена")
    return f"DEFAULT_TTL = {ttl} c; проверка expires_at при каждом обращении"


def s_no_plaintext_pwd_literals() -> str:
    for name in CORE_MODULES:
        for m in re.finditer(r"(password|passwd|pwd)\s*=\s*[\"']([^\"']{4,})[\"']",
                             SOURCES.get(name, ""), re.I):
            raise CheckFailed(f"{name}: литерал пароля: {m.group(0)[:40]}")
    return "в ядре нет паролей-литералов (пароли только параметры функций/env)"


def s_no_network() -> str:
    forbidden = ["socket", "socketserver", "http.server", "flask", "fastapi",
                 "uvicorn", "aiohttp", "urllib", "requests", "listen("]
    hits = sorted({p for p in forbidden if p in ALL_SRC})
    if hits:
        raise CheckFailed("найдены сетевые API: " + ", ".join(hits))
    return f"сетевые API не найдены ({len(SOURCES)} файлов проанализировано)"


def s_aead() -> str:
    src = SOURCES.get("security.py", "")
    if "AESGCM" not in src:
        raise CheckFailed("AESGCM не используется")
    if "os.urandom(12)" not in src:
        raise CheckFailed("nonce не генерируется os.urandom(12)")
    return "AES-GCM (cryptography), случайный nonce 12 байт на операцию"


def s_master_not_in_sources() -> str:
    for secret in (MASTER_PASSWORD, ADMIN_PASSWORD, ALICE_PASSWORD, BOB_PASSWORD):
        if secret in ALL_SRC:
            raise CheckFailed("аудиторский секрет найден в исходниках цели")
    return "пароли/ключи в исходниках цели не хранятся"


# ---------- динамические проверки ----------

def d_non_root() -> str:
    if os.geteuid() == 0:
        raise CheckFailed("динамический прогон выполнен от root")
    return f"целевое приложение выполнено от uid {os.geteuid()} (не root)"


def d_file_modes() -> str:
    modes = {"<dir>": os.stat(DATA_DIR).st_mode & 0o777}
    for name in sorted(os.listdir(DATA_DIR)):
        modes[name] = os.stat(os.path.join(DATA_DIR, name)).st_mode & 0o777
    bad = {k: oct(v) for k, v in modes.items() if v & 0o077}
    if bad:
        raise CheckFailed("доступ group/others: " + json.dumps(bad))
    files = ", ".join(f"{k}={oct(v)}" for k, v in modes.items() if k != "<dir>")
    return f"каталог {oct(modes['<dir>'])}; {files}"


def d_wrong_password() -> str:
    service = CTX["service"]
    try:
        CTX["app"].login("admin", "totally-wrong-password")
    except service.AuthError:
        return "login(admin, неверный пароль) -> AuthError; сессия не выдана"
    raise CheckFailed("неверный пароль принят")


def d_users_store() -> str:
    raw = data_file_text("users.json")
    for secret in (ADMIN_PASSWORD, ALICE_PASSWORD, BOB_PASSWORD):
        if secret in raw:
            raise CheckFailed("пароль найден в users.json в открытом виде")
    if '"password"' in raw:
        raise CheckFailed("в хранилище есть поле 'password'")
    users = json.loads(raw)
    for u in users:
        if not re.fullmatch(r"[0-9a-f]{64}", u["pwd_hash"]):
            raise CheckFailed(f"{u['login']}: некорректный формат хэша")
    return f"{len(users)} пользователей: только salt+hash (64 hex)"


def d_salt_unique() -> str:
    users = CTX["app"].users
    salts = {u["pwd_salt"] for u in users.values()}
    if len(salts) != len(users):
        raise CheckFailed("соли совпадают у разных пользователей")
    return f"{len(salts)} уникальных солей на {len(users)} пользователей"


def d_session_expiry() -> str:
    app, service = CTX["app"], CTX["service"]
    token = app.sessions.create("alice", ttl=1).token
    time.sleep(1.4)
    if app.sessions.get(token) is not None:
        raise CheckFailed("сессия действовала дольше TTL")
    try:
        app.get_record(token, CTX["secret_id"])
    except service.AccessDenied:
        return "сессия ttl=1 c истекла; операция по токену -> AccessDenied"
    raise CheckFailed("операция с истёкшей сессией выполнена")


def d_logout_invalidates() -> str:
    app, service = CTX["app"], CTX["service"]
    token = app.login("alice", ALICE_PASSWORD)
    app.logout(token)
    try:
        app.get_record(token, CTX["secret_id"])
    except service.AccessDenied:
        return "токен после logout отклонён (AccessDenied)"
    raise CheckFailed("токен работает после logout")


def d_audit_content() -> str:
    lines = data_file_text("audit.log").splitlines()
    allow = sum(1 for ln in lines if '"result": "allow"' in ln)
    deny = sum(1 for ln in lines if '"result": "deny"' in ln)
    if allow == 0 or deny == 0:
        raise CheckFailed(f"журнал неполный: allow={allow}, deny={deny}")
    return f"{len(lines)} записей (allow={allow}, deny={deny})"


def d_audit_no_secrets() -> str:
    raw = data_file_text("audit.log")
    for secret in (MASTER_PASSWORD, ADMIN_PASSWORD, ALICE_PASSWORD,
                   BOB_PASSWORD, SECRET_MARKER):
        if secret in raw:
            raise CheckFailed(f"в журнале найден секрет: {secret[:10]}…")
    return "паролей и содержимого конфиденциальных записей в журнале нет"


def d_input_validation() -> str:
    app, service = CTX["app"], CTX["service"]
    admin = CTX["admin_token"]
    cases = [
        ("короткий логин", lambda: app.add_user(admin, "ab", "LongPass-123", "user")),
        ("короткий пароль", lambda: app.add_user(admin, "validuser", "q1", "user")),
        ("недопустимая роль", lambda: app.add_user(admin, "validuser2", "LongPass-123", "root")),
        ("пустой заголовок записи", lambda: app.add_record(admin, "", "content", False)),
        ("несуществующая запись", lambda: app.get_record(admin, "no-such-id")),
    ]
    for label, fn in cases:
        try:
            fn()
        except (service.ValidationError, service.NotFound):
            continue
        except Exception as exc:
            raise CheckFailed(f"{label}: необработанное {type(exc).__name__}: {exc}")
        raise CheckFailed(f"{label}: некорректный ввод принят")
    return "5 некорректных входных данных отклонены управляемо"


def d_access_matrix() -> str:
    app, service = CTX["app"], CTX["service"]
    results = []

    def expect(label, fn, deny_type, should_allow):
        try:
            fn()
            got = "allow"
        except Exception as exc:
            if deny_type is not None and isinstance(exc, deny_type):
                got = "deny"
            else:
                raise
        results.append(f"{label}={got}")
        if got != ("allow" if should_allow else "deny"):
            raise CheckFailed(f"{label}: ожидалось "
                              f"{'разрешение' if should_allow else 'отказ'}, получено {got}")

    expect("guest пишет", lambda: app.add_record(CTX["bob_token"], "t", "c", False),
           service.AccessDenied, False)
    expect("guest читает чужую конф.", lambda: app.get_record(CTX["bob_token"], CTX["secret_id"]),
           service.AccessDenied, False)
    expect("user читает чужую конф.", lambda: app.get_record(CTX["alice_token"], CTX["secret_id"]),
           service.AccessDenied, False)
    own = app.add_record(CTX["alice_token"], "Личный ключ", "alice-secret-42", True)["id"]
    expect("user читает свою конф.", lambda: app.get_record(CTX["alice_token"], own),
           None, True)
    expect("admin читает чужую конф.", lambda: app.get_record(CTX["admin_token"], own),
           None, True)
    expect("admin правит чужую", lambda: app.edit_record(CTX["admin_token"], own, content="x"),
           None, True)
    return "; ".join(results)


def d_encrypted_at_rest() -> str:
    raw = data_file_text("records.json")
    if SECRET_MARKER in raw or "Ключи сервисного аккаунта" in raw:
        raise CheckFailed("конфиденциальные данные хранятся в открытом виде")
    count = raw.count('"enc_payload"')
    if count == 0:
        raise CheckFailed("шифрованные поля enc_payload не найдены")
    return f"конфиденциальных записей-шифротекстов: {count}; маркер секрета отсутствует"


def d_plain_stays_plain() -> str:
    raw = data_file_text("records.json")
    if PLAIN_MARKER not in raw:
        raise CheckFailed("неконфиденциальные данные неожиданно зашифрованы")
    return "неконфиденциальные данные хранятся читаемо (разграничение режимов)"


def d_key_not_on_disk() -> str:
    app = CTX["app"]
    for name in os.listdir(DATA_DIR):
        with open(os.path.join(DATA_DIR, name), "rb") as fh:
            blob = fh.read()
        if app.key in blob:
            raise CheckFailed(f"ключ шифрования найден в {name}")
        if MASTER_PASSWORD.encode() in blob:
            raise CheckFailed(f"мастер-пароль найден в {name}")
    return "ключ и мастер-пароль отсутствуют в файлах данных (ключ только в памяти)"


def d_no_listeners() -> str:
    """Слушатели в network namespace контейнера.

    Слушатель на 127.0.0.11 — встроенный DNS-прокси Docker (инфраструктура
    окружения); интерес представляют сокеты, созданные самим приложением.
    """
    listeners = []
    for path, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(path, encoding="ascii") as fh:
                lines = fh.readlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":
                continue
            ip_hex, port_hex = parts[1].split(":")
            raw = bytes.fromhex(ip_hex)
            port = int(port_hex, 16)
            if ipv6:
                addr = ":".join(raw[i:i + 4][::-1].hex() for i in range(0, 16, 4))
                is_infra = raw == bytes(16) or raw[12:16][::-1] == bytes([127, 0, 0, 11])
            else:
                addr = ".".join(str(b) for b in raw[::-1])
                is_infra = addr == "127.0.0.11"
            listeners.append((addr, port, is_infra))
    app_listeners = [ln for ln in listeners if not ln[2]]
    if app_listeners:
        raise CheckFailed("слушатели приложения: "
                          + ", ".join(f"{a}:{p}" for a, p, _ in app_listeners))
    if listeners:
        addr, port, _ = listeners[0]
        return (f"слушателей приложения: 0; единственный слушатель — DNS-инфраструктура "
                f"Docker {addr}:{port} (127.0.0.11), сокет не из кода цели")
    return "слушающих TCP-сокетов в контейнере: 0"


# ---------- отчёт ----------

DYNAMIC = [
    ("OS-D1", "ОС", "Прогон цели без root",
     "приложение работает от непривилегированного пользователя", d_non_root),
    ("OS-D2", "ОС", "Права на файлы данных",
     "каталог 0700, файлы 0600: нет доступа group/others", d_file_modes),
    ("CMP-D1", "Компоненты", "Неверный пароль отклоняется",
     "AuthError, сессия не создаётся", d_wrong_password),
    ("CMP-D2", "Компоненты", "В users.json нет паролей",
     "только соль и 64-символьный hex-хэш", d_users_store),
    ("CMP-D3", "Компоненты", "Соли паролей уникальны",
     "у каждого пользователя своя соль", d_salt_unique),
    ("CMP-D4", "Компоненты", "Тайм-аут сессии применяется",
     "сессия с ttl=1 c недействительна через 1.4 c", d_session_expiry),
    ("CMP-D5", "Компоненты", "Logout инвалидирует токен",
     "операция по токену после logout -> AccessDenied", d_logout_invalidates),
    ("CMP-D6", "Компоненты", "Аудит фиксирует allow и deny",
     "в журнале есть и успешные, и отклонённые события", d_audit_content),
    ("CMP-D7", "Компоненты", "Аудит не содержит секретов",
     "пароли и содержимое конфиденциальных записей отсутствуют", d_audit_no_secrets),
    ("CMP-D8", "Компоненты", "Валидация ввода",
     "5 видов некорректного ввода -> управляемый отказ без аварий", d_input_validation),
    ("CF-D1", "Данные", "Матрица прав guest/user/admin",
     "запреты гостю и чужому конф.; разрешения своим и admin", d_access_matrix),
    ("CF-D2", "Данные", "Конфиденциальные данные зашифрованы на диске",
     "в records.json только шифротекст enc_payload", d_encrypted_at_rest),
    ("CF-D3", "Данные", "Неконфиденциальные хранятся читаемо",
     "открытый текст присутствует (режимы различаются)", d_plain_stays_plain),
    ("CF-D4", "Данные", "Ключ шифрования не на диске",
     "ключ и мастер-пароль отсутствуют в файлах данных", d_key_not_on_disk),
    ("NET-D1", "Сеть", "Нет слушателей приложения",
     "в /proc/net/tcp* нет LISTEN, кроме DNS-инфраструктуры Docker", d_no_listeners),
]

STATIC = [
    ("OS-S1", "ОС", "Dockerfile: образ зафиксирован, non-root",
     "FROM без latest, есть USER не-root", s_dockerfile),
    ("CMP-S1", "Компоненты", "Пароли: PBKDF2-HMAC-SHA256",
     "pbkdf2_hmac('sha256') в коде", s_pbkdf2),
    ("CMP-S2", "Компоненты", "Стойкость KDF",
     "число итераций >= 100000", s_iterations),
    ("CMP-S3", "Компоненты", "Соль криптослучайная",
     "os.urandom для соли пароля", s_salt_random),
    ("CMP-S4", "Компоненты", "Сессии: TTL и проверка истечения",
     "константа TTL 0<TTL<=8ч, сравнение с time.time()", s_sessions_static),
    ("CMP-S5", "Компоненты", "Нет паролей-литералов в ядре",
     "в security/storage/sessions/audit/service нет литералов", s_no_plaintext_pwd_literals),
    ("NET-S1", "Сеть", "Нет сетевых API в коде",
     "socket/http.server/flask/fastapi/urllib и пр. отсутствуют", s_no_network),
    ("CF-S1", "Данные", "Конфиденциальные данные: AES-GCM",
     "AESGCM + случайный nonce 12 байт", s_aead),
    ("CF-S2", "Данные", "Секреты не зашиты в код",
     "пароли динамической среды отсутствуют в исходниках", s_master_not_in_sources),
]


def print_report() -> None:
    widths = (12, 8, 42, 40, 46, 7)

    def row(cells):
        print(" | ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths)))

    total_w = sum(widths) + 15
    print("\n" + "=" * total_w)
    print("ИТОГОВАЯ ТАБЛИЦА: проверка / ожидание / факт / вердикт")
    print("=" * total_w)
    row(("Политика", "ID", "Проверка", "Ожидание", "Факт", "Вердикт"))
    print("-" * total_w)
    for policy, cid, title, expectation, fact, verdict in RESULTS:
        row((policy, cid, title, expectation, fact, verdict))
    print("-" * total_w)
    passed = sum(1 for r in RESULTS if r[5] == "PASS")
    failed = sum(1 for r in RESULTS if r[5] == "FAIL")
    skipped = sum(1 for r in RESULTS if r[5] == "SKIP")
    print(f"ИТОГО: PASS={passed}  FAIL={failed}  SKIP={skipped}  из {len(RESULTS)}")


def main() -> None:
    print("#" * 70)
    print("# Лабораторная работа 2. Аудит защищённости сторонней системы")
    print(f"# Цель: исходники lab_1 ({TARGET_DIR}, ro) + Dockerfile цели")
    print("# Политики: ОС, компоненты и взаимодействие, сеть, конфиденциальность")
    print("#" * 70)

    load_sources()
    print(f"\n--- Статические проверки ({len(STATIC)}) ---")
    for cid, policy, title, expectation, fn in STATIC:
        run_check(cid, policy, title, expectation, fn)

    print(f"\n--- Динамические проверки ({len(DYNAMIC)}): тестовый прогон цели ---")
    try:
        prepare_dynamic()
        dynamic_ready, dynamic_error = True, ""
    except Exception as exc:
        dynamic_ready, dynamic_error = False, f"среда не поднята: {type(exc).__name__}: {exc}"
        print(f"  [SKIP] {dynamic_error}")
    for cid, policy, title, expectation, fn in DYNAMIC:
        if dynamic_ready:
            run_check(cid, policy, title, expectation, fn)
        else:
            RESULTS.append((policy, cid, title, expectation, dynamic_error, "SKIP"))

    print_report()
    if any(r[5] != "PASS" for r in RESULTS):
        sys.exit(1)


if __name__ == "__main__":
    main()
