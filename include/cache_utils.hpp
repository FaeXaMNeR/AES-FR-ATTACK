#pragma once

#include <cstdint>
#include <x86intrin.h>

namespace cache {

// Высокопроизводительный счётчик тактов процессора
inline uint64_t rdtsc() {
    unsigned int aux;
    uint64_t ret = __rdtscp(&aux);
    return ret;
}

inline void clflush(const void* addr) {
    _mm_clflush(addr);
}

inline void mfence() {
    _mm_mfence();
}

// Измерение времени доступа к памяти
// Возвращает количество тактов между flush и повторным доступом
inline uint64_t measure_access_time(volatile const void* addr) {
    uint64_t t1, t2;
    
    mfence();
    t1 = rdtsc();
    mfence();
    
    volatile uint8_t dummy = *static_cast<volatile const uint8_t*>(addr);
    (void)dummy;
    
    mfence();
    t2 = rdtsc();
    mfence();
    
    return t2 - t1;
}

inline uint64_t flush_and_reload(const void* addr) {
    clflush(addr);
    mfence();
    return measure_access_time(addr);
}

}