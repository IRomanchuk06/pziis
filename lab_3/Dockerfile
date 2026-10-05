FROM python:3.12-slim

# gdb + binutils (strings) нужны для снятия и анализа дампов памяти
RUN apt-get update \
    && apt-get install -y --no-install-recommends gdb binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY requirements.txt /work/requirements.txt
RUN pip install --no-cache-dir -r /work/requirements.txt

COPY app/ /work/app/

ENV PYTHONUNBUFFERED=1
CMD ["python3", "app/run_demo.py"]
