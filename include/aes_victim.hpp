#pragma once

#include <cstdint>
#include <array>
#include <cstring>

namespace victim {

constexpr size_t CACHE_LINE_SIZE = 64;

// T-таблицы AES (4 таблицы по 256 элементов × 4 байта)
struct alignas(CACHE_LINE_SIZE) T_Tables {
    uint32_t T0[256];
    uint32_t T1[256];
    uint32_t T2[256];
    uint32_t T3[256];
};

class AES128 {
public:
    AES128();
    
    void set_key(const uint8_t key[16]);
    
    void encrypt(const uint8_t in[16], uint8_t out[16]) const;
    
    // Доступ к T-таблицам (для атакующего)
    const T_Tables& get_tables() const { return tables_; }
    
    static constexpr size_t NUM_ROUNDS = 10;
    static constexpr size_t KEY_SCHEDULE_SIZE = 4 * (NUM_ROUNDS + 1);
    
private:
    T_Tables tables_;
    uint32_t round_keys_[KEY_SCHEDULE_SIZE];
    
    void init_tables();
    
    void key_expansion(const uint8_t key[16]);
    
    static uint8_t sbox(uint8_t x);
    
    // Умножение в GF(2^8)
    static uint8_t gmul(uint8_t a, uint8_t b);
};

}