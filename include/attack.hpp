#pragma once

#include "cache_utils.hpp"
#include "aes_victim.hpp"

#include <vector>
#include <array>
#include <cstdint>

namespace attack {

struct ProbeResult {
    size_t table_index;
    uint64_t access_time;
    bool is_hit;
};

struct RoundResult {
    std::array<uint64_t, 256> access_times;
    std::vector<size_t> hits;
};

class FlushReloadAttack {
public:
    FlushReloadAttack(const victim::AES128& victim_aes);
    
    void calibrate(size_t num_samples = 10000);
    void flush_all();
    ProbeResult probe(size_t index);
    RoundResult attack_round();
    uint8_t recover_key_byte(const std::vector<RoundResult>& rounds, 
                             uint8_t known_plaintext_byte);
    
    uint64_t get_threshold() const { return threshold_; }
    
private:
    const victim::AES128& victim_;
    uint64_t threshold_;
    std::array<const void*, 256> t0_lines_;
    
    void init_probe_addresses();
};

}