# Лабораторная работа 3. Анализ безопасности кода

Всё выполнение — в Docker-контейнере (python:3.12-slim + gdb/binutils +
cryptography). На хосте нужны только Docker и Docker Compose.

## Запуск

```bash
./run.sh
```

Одна команда: собирает образ, поднимает контейнер (с `--cap-add=SYS_PTRACE`
и `seccomp=unconfined` — необходимо для снятия дампов памяти через gdb),
выполняет полную демонстрацию и сохраняет все артефакты в `demo_output/`.

Ручной интерактивный запуск приложения (по желанию):

```bash
docker compose -p lab_3 run --rm demo python3 app/main.py --mode safe    # или --mode unsafe
```

## Что делает демонстрация (`app/run_demo.py`)

1. **Интерактивные сессии** (`session_safe.transcript.txt`,
   `session_unsafe.transcript.txt`) — реальный диалог с консольным UI:
   добавление конфиденциальных/неконфиденциальных данных и паролей, чтение,
   проверка пароля, обновление, удаление, невалидный ввод.
2. **Замеры ОЗУ/CPU** (`metrics.md`, `metrics.csv`, `bench_log.txt`) —
   VmRSS из `/proc/self/status` до/после операций и `time.process_time()`.
3. **Дампы памяти** (`dumps/`) — 3 точки (после ввода, после обновления,
   после удаления) × 2 режима (safe/unsafe). Снятие: `gdb -p <pid> -batch
   -ex 'gcore …'`. Анализ: `strings -a` + поиск случайно сгенерированных
   маркеров секретов (`dumps_analysis.md`, `*.matches.txt`, `*.strings.txt`,
   окна памяти `evidence_*.txt`).

Строки `>>> …` в транскриптах — команды, реально отправленные драйвером во
вход приложения (`<значение скрыто>` — секретные значения, они приведены в
`dumps/tokens.txt`). Приглашения ввода печатаются без перевода строки, поэтому
в транскрипте они «склеены» со следующей строкой вывода.

## Ключевой результат

В дампах **unsafe**-режима все секреты (мастер-пароль, конфиденциальные
данные, пароль, в т.ч. «удалённые») находятся; в дампах **safe**-режима
секретов нет — только намеренно хранимые открыто неконфиденциальные данные.
Подробности: `demo_output/dumps/dumps_analysis.md`, отчёт `report/report.md`.

## Структура

```
lab_3/
├── app/
│   ├── vault.py      # SafeVault (AES-GCM, PBKDF2, bytearray, затирание) и UnsafeVault
│   ├── main.py       # интерактивный консольный UI (режимы safe/unsafe)
│   ├── bench.py      # замеры RSS/CPU -> demo_output/metrics.{md,csv}
│   └── run_demo.py   # драйвер демонстрации (сессии, bench, дампы, анализ)
├── demo_output/      # артефакты прогона (создаётся run.sh)
├── report/report.md  # отчёт
├── Dockerfile, docker-compose.yml, run.sh, requirements.txt
```

PDF с условием лежит в корне папки и демонстрацией не изменяется.
