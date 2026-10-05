FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/app

COPY app/ /srv/app/

RUN pip install --no-cache-dir cryptography==44.0.1 \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /srv/data \
    && chown -R appuser:appuser /srv/app /srv/data

USER appuser

CMD ["python", "demo.py"]
