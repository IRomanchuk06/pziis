// Лабораторная работа № 4. Генерация случайных чисел.
// Пункт 3: криптографический генератор CryptGenRandom (CryptoAPI, <wincrypt.h>).
//
// Используются функции из примера методички:
//     CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
//     CryptGenRandom(hProv, cbGoop, lpGoop);
//     CryptReleaseContext(hProv, 0);
//
// Предназначен для компиляции кросс-компилятором MinGW под Windows:
//     x86_64-w64-mingw32-g++ -O2 -o gen_crypt.exe gen_crypt.cpp -ladvapi32
// Запуск (Windows / wine): gen_crypt.exe <выходной_файл> <кол-во_байт>
//
// Примечание: для MS VS 6.0 может потребоваться #define _WIN32_WINNT 0x0500
// (см. сноску в методичке); MinGW-заголовки содержат нужные объявления сразу.

#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    const char*          path  = (argc > 1) ? argv[1] : "crypt_out.bin";
    const unsigned long  total = (argc > 2) ? strtoul(argv[2], 0, 10) : 1048576UL;

    HCRYPTPROV hProv = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::fprintf(stderr, "CryptAcquireContext failed, GetLastError()=%lu\n",
                     static_cast<unsigned long>(GetLastError()));
        return 1;
    }

    FILE* out = std::fopen(path, "wb");
    if (out == NULL) {
        std::fprintf(stderr, "error: cannot open %s for writing\n", path);
        CryptReleaseContext(hProv, 0);
        return 2;
    }

    // Криптографический ГСЧ не требует memset буфера: CryptGenRandom
    // перезаписывает все запрошенные байты. Буфер 64 КиБ, цикл записи.
    static BYTE lpGoop[65536];
    unsigned long written = 0;
    int failed = 0;

    while (written < total) {
        DWORD cbGoop = static_cast<DWORD>(total - written);
        if (cbGoop > sizeof(lpGoop)) cbGoop = sizeof(lpGoop);

        if (!CryptGenRandom(hProv, cbGoop, lpGoop)) {
            std::fprintf(stderr, "ошибка генерации данных, GetLastError()=%lu\n",
                         static_cast<unsigned long>(GetLastError()));
            failed = 1;
            break;
        }
        if (std::fwrite(lpGoop, 1, cbGoop, out) != cbGoop) {
            std::fprintf(stderr, "error: write failed\n");
            failed = 1;
            break;
        }
        written += cbGoop;
    }

    std::fclose(out);

    if (hProv) CryptReleaseContext(hProv, 0);

    if (failed) return 3;

    std::printf("OK: CryptGenRandom wrote %lu bytes to %s\n", written, path);
    return 0;
}
