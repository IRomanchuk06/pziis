# Контейнер-клиент: генератор трафика и среда запуска анализатора.
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# curl — реальные HTTP-запросы; openssh-client + sshpass — реальные SSH-попытки;
# requests + paramiko — проверки готовности и программная SSH-сессия.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass curl \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir requests paramiko

WORKDIR /workspace

CMD ["sleep", "infinity"]
