# Лабораторная работа № 4 «Генерация случайных чисел».
# Вся работа выполняется внутри docker-контейнеров; на хосте — только docker.

# --- base: компилятор g++ и python3 ---------------------------------------
FROM debian:bookworm-slim AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        g++ \
        python3 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work

# --- lab4: основной образ + кросс-компилятор MinGW для CryptGenRandom ------
FROM base AS lab4
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        g++-mingw-w64-x86-64 \
 && rm -rf /var/lib/apt/lists/*
CMD ["bash", "/work/scripts/demo.sh"]

# --- winetest: попытка запуска gen_crypt.exe под wine (best-effort) --------
FROM lab4 AS winetest
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        wine \
        wine64 \
 && rm -rf /var/lib/apt/lists/*
CMD ["bash", "/work/scripts/wine_run.sh"]
