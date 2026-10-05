FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        nmap \
        iproute2 \
        openssh-client \
        sshpass \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY traffic_gen.py /opt/traffic_gen.py

CMD ["sleep", "infinity"]
