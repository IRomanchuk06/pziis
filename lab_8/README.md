# Лабораторная работа №8. Управление доступом к приложениям и системам баз данных

Вариант: **СУБД MySQL** (контейнер `mysql:8.4`).

Всё выполнение — строго внутри Docker: СУБД работает в контейнере, скрипты
работы с БД (Python, `mysql-connector-python`) выполняются в отдельном
контейнере-клиенте на базе `python:3.12-slim`. На хосте ничего не
устанавливается и не запускается (используются только `docker` / `docker compose`).
Порты наружу не публикуются: клиенты и СУБД общаются по изолированной
внутренней сети compose (`lab8net`, `internal: true`).

## Запуск (полный цикл демонстрации одной командой)

```bash
./run.sh
```

`run.sh` выполняет:

1. `scripts/install.sh` — установка СУБД: `docker compose up -d --build`,
   ожидание готовности по healthcheck, создание тестовой БД `company`
   (таблицы `employees` — id, name, salary, passport_no; и `audit_log`);
2. `scripts/setup_access.py` — настройка механизма контроля доступа:
   три роли (admin / app_user / guest), GRANT-скрипты, вывод `SHOW GRANTS`;
3. `scripts/check_policy.py` — проверка корректности политики безопасности:
   матрица из 31 теста (SELECT / INSERT / UPDATE / DELETE / DDL / чтение
   запрещённых колонок / GRANT) от имени каждой роли; код возврата != 0 при FAIL;
4. демонстрация отрицательных кейсов (живые попытки запрещённых операций
   от имени guest и app_user с реальными ответами СУБД);
5. `scripts/uninstall.sh` — удаление СУБД и созданных объектов
   (`docker compose down -v`, тома/сеть/локальный образ).

Весь вывод по шагам сохраняется в `demo_output/01..05_*.log`.

## Роли (политика безопасности по методичке)

| Роль     | Привилегии |
|----------|------------|
| `admin`  | администратор системы: `GRANT ALL PRIVILEGES ON *.* ... WITH GRANT OPTION` — полный доступ ко всем подсистемам, максимальные привилегии |
| `app_user` | пользователь: частичные права, выданные администратором — `SELECT(id,name,salary)`, `INSERT(id,name,salary)`, `UPDATE(name,salary)` на `company.employees` (без `DELETE`, без колонки `passport_no` — column privileges); `SELECT, INSERT` на `company.audit_log` |
| `guest`  | гость: только чтение отдельных фрагментов — `SELECT` на представление `company.v_public` (id, name); `salary` и `passport_no` недоступны |

## Структура

```text
lab_8/
├── docker-compose.yml      # project name lab_8: mysql:8.4 + клиент python:3.12-slim
├── .env                    # переменные (пароль root и пароли ролей, лабовые значения)
├── client/Dockerfile       # образ клиента: python:3.12-slim + pip mysql-connector-python
├── sql/schema.sql          # БД company, таблицы employees и audit_log
├── scripts/
│   ├── install.sh          # программа 1: установка СУБД
│   ├── setup_access.py     # программа 2: настройка контроля доступа (роли, GRANT)
│   ├── check_policy.py     # программа 3: проверка политики (матрица тестов)
│   └── uninstall.sh        # программа 4: удаление СУБД и её объектов
├── run.sh                  # полный цикл демонстрации
├── demo_output/            # только реально захваченный вывод шагов
├── report/report.md        # отчёт
└── README.md
```

## Отдельные команды (внутри цикла run.sh)

```bash
docker compose up -d --build                                          # запуск стека
docker compose exec -T client python scripts/setup_access.py          # настройка ролей
docker compose exec -T client python scripts/check_policy.py          # проверка политики
docker compose down -v --rmi local --remove-orphans                   # полное удаление
```

## Замечания

- Пароль root СУБД задаётся через переменную compose `MYSQL_ROOT_PASSWORD`
  (файл `.env`, лабовое значение `lab8root`); пароли ролей — аналогично
  (`LAB8_ADMIN_PASSWORD`, `LAB8_USER_PASSWORD`, `LAB8_GUEST_PASSWORD`).
- При инициализации MySQL может потребоваться ~30–60 с; `install.sh`
  ожидает состояние `healthy` по healthcheck.
- `uninstall.sh` удаляет контейнеры, внутреннюю сеть, том `mysql_data`
  (данные БД) и локально собранный образ клиента; базовый образ
  `mysql:8.4` остаётся в локальном кэше Docker (повторный запуск не
  требует повторного скачивания).
