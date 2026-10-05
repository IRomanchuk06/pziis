# Лабораторная работа №10. Управление доступом к объектам ОС Linux.
# Окружение: чистый Ubuntu 24.04 (в контейнере скрипты работают от root —
# это штатно для настройки пользователей, групп и прав доступа).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# sudo   — административные привилегии пользователя iit21 (шаг 4 задания);
# procps — ps/pkill для диагностики и очистки процессов.
RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo procps \
 && rm -rf /var/lib/apt/lists/*

# Скрипты лабораторной работы (владелец root:root, доступны всем на чтение/запуск)
COPY scripts/ /opt/lab/scripts/
RUN chmod 755 /opt/lab/scripts/*.sh

WORKDIR /opt/lab

# Никаких --privileged не требуется: обычный docker run / compose up.
CMD ["bash", "/opt/lab/scripts/run_demo.sh"]
