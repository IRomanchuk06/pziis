#!/bin/bash
# Точка входа контейнера suricata.
#
# Режим "gateway" (используется при compose up):
#   контейнер работает L3-шлюзом между outside- и secure-сетями
#   (ip_forward), но движок Suricata НЕ запущен - фаза "ДО".
#
# Режим "ids" (запускается run.sh):
#   загружает правила, генерирует конфиг и запускает движок - фаза "ПОСЛЕ".
set -u

OUTSIDE_IP="172.28.100.3"
HOME_NET_CIDR="${HOME_NET_CIDR:-172.29.100.0/24}"
export HOME_NET_CIDR

log() { echo "[suricata-entrypoint] $*"; }

find_if_by_ip() {
    ip -o -4 addr show | awk -v ip="$1" '$4 == ip"/24" {print $2; exit}'
}

setup_forwarding() {
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    log "ip_forward=1 (контейнер - маршрутизатор между сетями стенда)"
}

case "${1:-}" in
    gateway)
        setup_forwarding
        log "режим шлюза; движок Suricata отключён (фаза ДО)"
        exec sleep infinity
        ;;
    ids)
        setup_forwarding
        IF_OUT="$(find_if_by_ip "$OUTSIDE_IP")"
        if [ -z "$IF_OUT" ]; then
            log "ERROR: интерфейс с адресом $OUTSIDE_IP не найден"
            ip -o -4 addr show
            exit 1
        fi
        log "outside-интерфейс для af-packet: $IF_OUT"

        mkdir -p /etc/suricata/rules /var/log/suricata
        cp /local.rules /etc/suricata/rules/local.rules
        cp /etc/suricata/classification.config /etc/suricata/reference.config \
           /etc/suricata/rules/ 2>/dev/null || true
        # Глушим шум служебных кадров моста (LLDP/STP -> "Ethertype unknown")
        printf 'suppress gen_id 1, sig_id 2200121\n' > /etc/suricata/rules/threshold.config

        # Загрузка публичного набора правил ET Open (если недоступна сеть -
        # остаёмся на local.rules, о чём честно пишем в лог).
        if [ ! -f /etc/suricata/rules/suricata.rules ]; then
            log "suricata-update: загрузка набора правил ET Open..."
            if timeout 300 suricata-update -o /etc/suricata/rules -v >/tmp/update.log 2>&1; then
                log "ET Open загружены: $(grep -c '^alert\|^# alert' /etc/suricata/rules/suricata.rules 2>/dev/null || echo '?') строк"
            else
                log "WARN: suricata-update не удался (нет доступа к репозиторию правил), работаем на local.rules"
                tail -3 /tmp/update.log || true
            fi
        fi

        python3 /genconf.py "$IF_OUT"
        log "запуск движка Suricata (IDS, af-packet на $IF_OUT)"
        # NOTE: в Suricata 8 (образ jasonish/suricata:8.0.7) без явного
        # аргумента захвата движок печатает usage и завершается, поэтому
        # af-packet интерфейс задаётся и в конфиге, и в командной строке.
        exec suricata -c /etc/suricata/generated.yaml --af-packet="$IF_OUT"
        ;;
    *)
        echo "usage: $0 {gateway|ids}" >&2
        exit 2
        ;;
esac
