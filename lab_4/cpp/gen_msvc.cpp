// Лабораторная работа № 4. Генерация случайных чисел.
// Пункт 2: датчик rand() как в MS Visual Studio.
//
// Формула MSVC rand() (как в CRT Microsoft):
//     State = State * 214013 + 2531011;   (арифметика по модулю 2^32)
//     return (State >> 16) & 0x7fff;
//
// Программа эмулирует этот датчик и записывает в файл младшие байты
// последовательных значений rand() (аналог примера из методички, где
// memcpy копирует 1 байт из DWORD с результатом rand()).
//
// Сборка: g++ -O2 -o gen_msvc gen_msvc.cpp
// Запуск: ./gen_msvc <выходной_файл> <кол-во_байт>

#include <cstdio>
#include <cstdint>
#include <cstdlib>

int main(int argc, char** argv) {
    const char*      path = (argc > 1) ? argv[1] : "msvc_rand.bin";
    const uint32_t   n    = (argc > 2) ? static_cast<uint32_t>(strtoul(argv[2], 0, 10))
                                       : 20000000u; // 20 МБ младших байтов

    // Аналог srand(0) из примера методички: начальное состояние = 0.
    uint32_t state = 0u;

    FILE* out = std::fopen(path, "wb");
    if (out == 0) {
        std::fprintf(stderr, "error: cannot open %s for writing\n", path);
        return -1;
    }

    for (uint32_t i = 0; i < n; ++i) {
        state = state * 214013u + 2531011u;      // State = State * 214013 + 2531011 (mod 2^32)
        const uint16_t r = static_cast<uint16_t>((state >> 16) & 0x7fffu);
        const uint8_t  b = static_cast<uint8_t>(r & 0xffu); // младший байт rand()
        if (std::fwrite(&b, 1, 1, out) != 1) {
            std::fprintf(stderr, "error: write failed\n");
            std::fclose(out);
            return -2;
        }
    }

    std::fclose(out);
    std::printf("OK: wrote %u bytes of MSVC rand() low bytes to %s\n", n, path);
    return 0;
}
