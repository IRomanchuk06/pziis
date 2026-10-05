// Лабораторная работа № 4. Генерация случайных чисел.
// Пункт 4: собственная реализация генератора из таблицы 1 методички.
//
// Используется формула (1) из таблицы 1:
//
//     x_{t+1} = (1176*x_t + 1476*x_{t-1} + 1776*x_{t-2}) mod (2^32 - 5)
//
// Модуль m = 2^32 - 5 = 4294967291 (простое число), период T_max ~ 2^96.
// Значения записываются в файл как 32-битные целые в порядке little-endian
// (формат файла случайных целых для батареи DIEHARD, файл > 11 МБ).
//
// Сборка: g++ -O2 -o gen_own gen_own.cpp
// Запуск: ./gen_own <выходной_файл> <кол-во_32бит_слов>

#include <cstdio>
#include <cstdint>
#include <cstdlib>

static const uint64_t M = (1ULL << 32) - 5ULL; // 2^32 - 5 = 4294967291

struct OwnGen {
    uint64_t x0, x1, x2; // x_{t-2}, x_{t-1}, x_t
    explicit OwnGen(uint64_t s0, uint64_t s1, uint64_t s2)
        : x0(s0 % M), x1(s1 % M), x2(s2 % M) {}

    uint64_t next() {
        // x_{t+1} = (1176*x_t + 1476*x_{t-1} + 1776*x_{t-2}) mod (2^32 - 5)
        const uint64_t xn = (1176ULL * x2 + 1476ULL * x1 + 1776ULL * x0) % M;
        x0 = x1;
        x1 = x2;
        x2 = xn;
        return xn;
    }
};

static void put_u32le(FILE* out, uint64_t v) {
    const unsigned char b[4] = {
        static_cast<unsigned char>(v        & 0xffu),
        static_cast<unsigned char>((v >> 8) & 0xffu),
        static_cast<unsigned char>((v >> 16) & 0xffu),
        static_cast<unsigned char>((v >> 24) & 0xffu)
    };
    std::fwrite(b, 1, 4, out);
}

int main(int argc, char** argv) {
    const char*    path = (argc > 1) ? argv[1] : "own_gen.bin";
    const uint32_t n    = (argc > 2) ? static_cast<uint32_t>(strtoul(argv[2], 0, 10))
                                     : 3000000u; // 3 000 000 слов x 4 байта = 12 МБ > 11 МБ

    // Начальное состояние (произвольные ненулевые seed'ы).
    OwnGen gen(0x1a2b3c4dULL, 0x9e3779b9ULL, 0x12345678ULL);

    FILE* out = std::fopen(path, "wb");
    if (out == 0) {
        std::fprintf(stderr, "error: cannot open %s for writing\n", path);
        return -1;
    }

    for (uint32_t i = 0; i < n; ++i) {
        put_u32le(out, gen.next());
    }

    std::fclose(out);
    std::printf("OK: wrote %u x 4 bytes (= %u bytes) from generator (1) of Table 1 to %s\n",
                n, n * 4u, path);
    return 0;
}
