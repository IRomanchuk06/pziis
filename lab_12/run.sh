#!/usr/bin/env bash
# =============================================================================
# Лабораторная работа №12 "Совершенствование безопасности удалённых серверов"
# Вариант: IDS/IPS Suricata.
#
# Одна команда выполняет весь сценарий:
#   1. поднимает стенд (docker compose);
#   2. фаза ДО  - IDS отключена, генератор трафика (нормальный + атаки),
#                 сбор сырых логов nginx/sshd;
#   3. включает движок Suricata (IDS, af-packet, ET Open + local.rules);
#   4. фаза ПОСЛЕ - тот же генератор, сбор fast.log/eve.json с алертами;
#   5. analysis/analyze.py -> demo_output/before_after.txt.
#
# Портов наружу стенд не публикует.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

DEMO=demo_output
LOGDIR=data/suricata
ENGINE_WAIT=420      # секунд на ожидание загрузки правил ET Open

log()  { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

# python3 для анализатора: на хосте, иначе внутри контейнера attacker
run_analyze() {
    if command -v python3 >/dev/null 2>&1; then
        DEMO_DIR="$PWD/$DEMO" python3 analysis/analyze.py
    else
        docker compose exec -T attacker python3 /opt/analyze.py
    fi
}

wait_engine() {
    log "Ожидание готовности движка Suricata (загрузка ~53k правил ET Open)..."
    local i=0
    while [ "$i" -lt "$ENGINE_WAIT" ]; do
        if docker compose exec -T suricata sh -c \
            'test -f /var/log/suricata/suricata.log && grep -qi "engine started" /var/log/suricata/suricata.log' 2>/dev/null; then
            docker compose exec -T suricata sh -c \
                'grep -E "rule files processed|engine started" /var/log/suricata/suricata.log | tail -2'
            log "Движок Suricata готов."
            return 0
        fi
        if ! docker compose exec -T suricata true 2>/dev/null; then
            die "Контейнер suricata недоступен"
        fi
        sleep 5
        i=$((i + 5))
    done
    docker compose logs suricata | tail -20 >&2 || true
    die "Suricata не запустилась за ${ENGINE_WAIT} c"
}

collect_server_logs() {  # $1 = подкаталог demo_output
    docker compose exec -T web sh -c 'cat /var/log/nginx/access.log 2>/dev/null' \
        > "$DEMO/$1/nginx_access.log"
    docker compose exec -T web sh -c 'cat /var/log/auth.log 2>/dev/null' \
        > "$DEMO/$1/auth.log"
    docker compose exec -T web sh -c 'cat /var/log/nginx/error.log 2>/dev/null' \
        > "$DEMO/$1/nginx_error.log" || true
}

log "1/6. Сборка и запуск стенда (project: lab_12)"
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
# Логи Suricata создаются в контейнере от root - чистим их тоже из контейнера
docker run --rm -v "$PWD/data:/w" debian:bookworm-slim \
    sh -c 'rm -rf /w/suricata && mkdir -p /w/suricata' >/dev/null 2>&1 || true
rm -rf "$DEMO"
mkdir -p "$DEMO/before" "$DEMO/after" "$LOGDIR"
docker compose up -d --build

log "Ожидание защищаемого сервера (nginx+sshd через шлюз suricata)..."
ready=""
for i in $(seq 1 30); do
    code=$(docker compose exec -T attacker curl -s -o /dev/null -w '%{http_code}' -m 4 \
        http://172.29.100.10/api/status 2>/dev/null || echo 000)
    if [ "$code" = "200" ]; then ready=yes; break; fi
    sleep 2
done
[ -n "$ready" ] || { docker compose logs web suricata 2>&1 | tail -20 >&2; die "web недоступен через шлюз"; }
echo "Сервер отвечает (HTTP 200) - трафик attacker->web проходит через контейнер suricata."

log "2/6. Фаза ДО: IDS отключена; генерация нормального трафика и атак"
docker compose exec -T attacker python3 /opt/traffic_gen.py --phase full \
    > "$DEMO/before/attacker_traffic.log" 2>&1
tail -8 "$DEMO/before/attacker_traffic.log"
collect_server_logs before
# fast.log в фазе ДО отсутствует по определению (движок ещё не запущен)
touch "$DEMO/before/fast.log"

log "3/6. Включение IDS Suricata (af-packet, IDS-режим, ET Open + local.rules)"
# Ротация журналов сервера, чтобы фаза ПОСЛЕ содержала только свой трафик
docker compose exec -T web sh -c ': > /var/log/nginx/access.log; : > /var/log/auth.log; : > /var/log/nginx/error.log' 2>/dev/null || true
docker compose exec -d suricata /bin/bash -c '/entrypoint.sh ids >/tmp/ids.log 2>&1'
wait_engine

log "4/6. Фаза ПОСЛЕ: тот же генератор против защищаемого сервера"
docker compose exec -T attacker python3 /opt/traffic_gen.py --phase full \
    > "$DEMO/after/attacker_traffic.log" 2>&1
tail -8 "$DEMO/after/attacker_traffic.log"
sleep 5   # даём Suricata дописать события последнего потока
collect_server_logs after
docker compose exec -T suricata sh -c 'cat /var/log/suricata/fast.log'  > "$DEMO/after/fast.log"
docker compose exec -T suricata sh -c 'cat /var/log/suricata/eve.json'  > "$DEMO/after/eve.json"
docker compose exec -T suricata sh -c 'cat /var/log/suricata/suricata.log' > "$DEMO/after/suricata.log"
docker compose exec -T suricata sh -c 'cat /var/log/suricata/stats.log' > "$DEMO/after/stats.log"

log "5/6. Анализ результатов"
ALERTS=$(grep -c . "$DEMO/after/fast.log" || true)
if [ "${ALERTS:-0}" -eq 0 ]; then
    warn "fast.log пуст - алертов нет, анализ невозможен"
    run_analyze || true
    die "Ненулевых алертов не получено - проверьте правила и захват трафика"
fi
run_analyze || die "Анализ завершился с ошибкой"

log "6/6. Готово"
echo
echo "Файлы результатов:"
ls -la "$DEMO" "$DEMO"/before "$DEMO"/after | sed 's/^/  /'
echo
echo "Алертов в fast.log: $ALERTS"
echo "Сводка: $DEMO/before_after.txt"
