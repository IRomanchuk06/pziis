FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx \
        openssh-server \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Пользователь для SSH (для сценария брутфорса)
RUN useradd -m -s /bin/bash dev && echo 'dev:SuperSecret123' | chpasswd \
    && mkdir -p /run/sshd /var/www/html/static

COPY nginx-site.conf /etc/nginx/sites-available/default
COPY start.sh /start.sh
COPY index.html /var/www/html/index.html
COPY about.html /var/www/html/about.html
COPY style.css /var/www/html/static/style.css

RUN chmod +x /start.sh

EXPOSE 80 22

CMD ["/start.sh"]
