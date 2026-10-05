# SSH-сервер стенда лабораторной работы №11 (ubuntu:24.04 + openssh-server).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server moreutils \
 && rm -rf /var/lib/apt/lists/*

# Тестовый пользователь с парольной аутентификацией.
# Пароль лабовый (не секретные данные), задокументирован в README.
RUN useradd -m -s /bin/bash -c "Lab11 test user" labuser \
 && echo 'labuser:Lab11_Secret_Pass!' | chpasswd

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
