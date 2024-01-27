#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "bloom.h"

// set BLOOM_K bits based on id
void bloom_init(void *bloom, uint64_t id)
{
    memset(bloom, 0, BLOOM_M);

    // linear congruential generator
    uint64_t next = id;
    for (size_t i = 0; i < BLOOM_K; ++i) {
        next = next * 1103515245 + 12345;
        uint32_t r = (next / 65536) % 32768;
        uint32_t j = r % (BLOOM_M * 8);
        BLOOM_BITSET(((uint8_t*) bloom), j);
    }
}

void bloom_merge(void *bloom1, const void *bloom2)
{
    uint8_t *b1 = (uint8_t*) bloom1;
    uint8_t *b2 = (uint8_t*) bloom2;
    for (size_t i = 0; i < BLOOM_M; ++i) {
        b1[i] |= b2[i];
    }
}

void bloom_add(void *bloom, uint32_t id)
{
    uint8_t bloom_id[BLOOM_M];
    bloom_init(bloom_id, id);
    bloom_merge(bloom, bloom_id);
}

// count of bits set in bloom filter
uint16_t bloom_ones(const void *bloom)
{
    uint16_t ones = 0;

    for (size_t i = 0; i < (8 * BLOOM_M); ++i) {
        ones += (0 != BLOOM_BITTEST(((uint8_t*) bloom), i));
    }

    return ones;
}

bool bloom_test(const void *bloom, uint32_t id)
{
    uint8_t bloom_id[BLOOM_M]; 
    bloom_init(bloom_id, id);

    uint8_t *b = (uint8_t*) bloom;
    for (size_t i = 0; i < BLOOM_M; ++i) {
        if ((b[i] & bloom_id[i]) != bloom_id[i]) {
            return false;
        }
    }

    return true;
}

/*
// is this good?
static bool bloom_good(const uint8_t *bloom, uint16_t hop_count)
{
    if (bloom_test(bloom, gstate.own_id)) {
        // own id in bloom filter
        // either we saw the packet already or it is a bad bloom
        return false;
    }

    uint32_t ones = bloom_ones(bloom);

    if (hop_count == 0) {
        return false;
    } else {
        // if at most BLOOM_K bits are set per hop, then this bloom is ok 
        return (1000U * ones / (BLOOM_K * hop_count)) <= 2000;
    }
}*/

char *str_bloom(const void *bloom)
{
    static char buf[BLOOM_M * 8 + 1];
    char *cur = buf;
    for (size_t i = 0; i < (8 * BLOOM_M); ++i) {
        uint32_t bit = (0 != BLOOM_BITTEST(((uint8_t*) bloom), i));
        cur += sprintf(cur, "%"PRIu32, bit);
    }
    return buf;
}

/*
static void bloom_merge(uint8_t *bloom1, const uint8_t *bloom2)
{
    for (size_t i = 0; i < BLOOM_M; ++i) {
        bloom1[i] |= bloom2[i];
    }
}*/

void bloom_delete(void *bloom, uint32_t id)
{
    uint8_t *b = (uint8_t*) bloom;
    uint8_t bloom_id[BLOOM_M];
    bloom_init(bloom_id, id);
    //bloom_merge(bloom, &bloom_id[0]);

    for (size_t i = 0; i < BLOOM_M; ++i) {
        b[i] &= ~bloom_id[i];
    }
}

uint16_t bloom_similar_ones(void *bloom1, void *bloom2)
{
    uint8_t bloom[BLOOM_M] = {0};
    uint8_t *b1 = (uint8_t*) bloom1;
    uint8_t *b2 = (uint8_t*) bloom2;

    for (size_t i = 0; i < BLOOM_M; ++i) {
        bloom[i] = b1[i] & b2[i];
    }

    return bloom_ones(bloom);
}
