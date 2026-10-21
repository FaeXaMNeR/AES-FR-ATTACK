#include "aes_victim.hpp"
#include "aes_victim_cleansed.hpp"
#include "cache_utils.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <vector>

namespace {

double now_s() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

struct Metrics {
    double ns_per_block;
    double cycles_per_block;
    double mb_per_s;
};

template <class V>
Metrics measure_once(V& v, std::size_t n) {
    std::uint8_t pt[16], ct[16];
    for (int i = 0; i < 16; ++i) pt[i] = (std::uint8_t)(i * 7 + 1);
    volatile std::uint8_t sink = 0;

    // Прогрев
    for (int i = 0; i < 1000; ++i) {
        v.encrypt(pt, ct);
        sink ^= ct[i & 15];
    }

    const double t0 = now_s();
    const std::uint64_t c0 = cache::rdtsc();

    for (std::size_t i = 0; i < n; ++i) {
        v.encrypt(pt, ct);
        sink ^= ct[i & 15];
    }

    const std::uint64_t c1 = cache::rdtsc();
    const double t1 = now_s();

    const double sec = t1 - t0;
    Metrics m;
    m.ns_per_block     = sec * 1e9 / (double)n;
    m.cycles_per_block = (double)(c1 - c0) / (double)n;
    m.mb_per_s         = (double)n * 16.0 / sec / 1e6;
    return m;
}

template <class V>
Metrics measure_median(V& v, std::size_t n, int reps) {
    std::vector<Metrics> runs;
    runs.reserve((std::size_t)reps);
    for (int i = 0; i < reps; ++i) runs.push_back(measure_once(v, n));
    std::sort(runs.begin(), runs.end(),
              [](const Metrics& a, const Metrics& b) {
                  return a.ns_per_block < b.ns_per_block;
              });
    return runs[runs.size() / 2];
}

}  // namespace

int main(int argc, char** argv) {
    std::size_t n = 100000;
    int reps = 5;
    if (argc > 1) {
        const long v = std::strtol(argv[1], nullptr, 10);
        if (v > 0) n = (std::size_t)v;
    }
    if (argc > 2) {
        const long v = std::strtol(argv[2], nullptr, 10);
        if (v > 0) reps = (int)v;
    }

    const std::uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    victim::AES128 base;
    base.set_key(key);
    victim::AES128Cleansed cleansed;
    cleansed.set_key(key);

    const Metrics b = measure_median(base, n, reps);
    const Metrics c = measure_median(cleansed, n, reps);

    const double slowdown_ns = b.ns_per_block > 0.0
        ? c.ns_per_block / b.ns_per_block : 0.0;
    const double slowdown_cy = b.cycles_per_block > 0.0
        ? c.cycles_per_block / b.cycles_per_block : 0.0;
    const double tsc_mhz = b.ns_per_block > 0.0
        ? b.cycles_per_block / b.ns_per_block * 1000.0 : 0.0;

    std::printf("=============================================================\n");
    std::printf(" Скорость шифрования БЕЗ атакующего (медиана из %d прогонов)\n", reps);
    std::printf("=============================================================\n");
    std::printf(" блоков на прогон = %lu, размер блока = 16 байт\n", (unsigned long)n);
    std::printf(" TSC (оценка)     = %.1f МГц\n\n", tsc_mhz);

    std::printf(" вариант                       тактов/блок   нс/блок     МБ/с\n");
    std::printf(" ----------------------------  ------------  ---------  --------\n");
    std::printf(" базовая T-таблица             %12.1f  %9.1f  %8.1f\n",
                b.cycles_per_block, b.ns_per_block, b.mb_per_s);
    std::printf(" + сброс таблиц и предзагрузка %12.1f  %9.1f  %8.1f\n",
                c.cycles_per_block, c.ns_per_block, c.mb_per_s);
    std::printf("\n замедление контрмеры: %.1f× по времени, %.1f× по тактам\n",
                slowdown_ns, slowdown_cy);

    return 0;
}
