FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/app

COPY app/ /srv/app/

RUN pip install --no-cache-dir cryptography==44.0.1 \
    && useradd --create-home --uid 10002 auditor \
    && mkdir -p /srv/inspect /srv/work \
    && chown -R auditor:auditor /srv/inspect /srv/work

USER auditor

CMD ["python", "/srv/app/audit.py"]
