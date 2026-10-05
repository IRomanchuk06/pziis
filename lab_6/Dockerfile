# ЛР6: контейнер с OpenSSL 3.x (ubuntu:24.04, openssl ставится из apt)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY scripts/run_all.sh /scripts/run_all.sh
RUN chmod +x /scripts/run_all.sh

CMD ["bash", "/scripts/run_all.sh"]
