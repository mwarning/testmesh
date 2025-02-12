#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>

#include "bloom.h"


void bloom_init(void *bloom, uint64_t id, uint32_t bloom_m, uint32_t bloom_k)
{
    memset(bloom, 0, bloom_m);

    // linear congruential generator
    uint64_t next = id;
    for (size_t i = 0; i < bloom_k; ++i) {
        next = next * 1103515245 + 12345;
        uint32_t r = (next / 65536) % 32768;
        uint32_t j = r % (bloom_m * 8);
        BLOOM_BITSET(((uint8_t*) bloom), j);
    }
}

void bloom_merge(void *bloom1, const void *bloom2, uint32_t bloom_m)
{
    uint8_t *b1 = (uint8_t*) bloom1;
    uint8_t *b2 = (uint8_t*) bloom2;
    for (size_t i = 0; i < bloom_m; ++i) {
        b1[i] |= b2[i];
    }
}

void bloom_add(void *bloom, uint32_t id, uint32_t bloom_m, uint32_t bloom_k)
{
    uint8_t bloom_id[bloom_m];
    bloom_init(bloom_id, id, bloom_m, bloom_k);
    bloom_merge(bloom, bloom_id, bloom_m);
}

// count of bits set in bloom filter
uint16_t bloom_ones(const void *bloom, uint32_t bloom_m)
{
    uint16_t ones = 0;

    for (size_t i = 0; i < (8 * bloom_m); ++i) {
        ones += (0 != BLOOM_BITTEST(((uint8_t*) bloom), i));
    }

    return ones;
}

bool bloom_test(const void *bloom, uint32_t id, uint32_t bloom_m, uint32_t bloom_k)
{
    uint8_t bloom_id[bloom_m];
    bloom_init(bloom_id, id, bloom_m, bloom_k);

    uint8_t *b = (uint8_t*) bloom;
    for (size_t i = 0; i < bloom_m; ++i) {
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

char *str_bloom(const void *bloom, uint32_t bloom_m)
{
    assert(bloom_m <= 16);
    static char strbloombuf[4][16 * 8 + 1];
    static size_t strbloombuf_i = 0;
    char *buf = strbloombuf[++strbloombuf_i % 4];

    char *cur = buf;
    uint32_t bits = (8 * bloom_m);
    for (size_t i = 0; i < bits; ++i) {
        uint32_t bit = (0 != BLOOM_BITTEST(((uint8_t*) bloom), bits - 1 - i));
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

void bloom_delete(void *bloom, uint32_t id, uint32_t bloom_m, uint32_t bloom_k)
{
    uint8_t *b = (uint8_t*) bloom;
    uint8_t bloom_id[bloom_m];
    bloom_init(bloom_id, id, bloom_m, bloom_k);
    //bloom_merge(bloom, &bloom_id[0]);

    for (size_t i = 0; i < bloom_m; ++i) {
        b[i] &= ~bloom_id[i];
    }
}

uint16_t bloom_similar_ones(void *bloom1, void *bloom2, uint32_t bloom_m)
{
    uint8_t bloom[bloom_m];
    memset(bloom, 0, bloom_m);
    uint8_t *b1 = (uint8_t*) bloom1;
    uint8_t *b2 = (uint8_t*) bloom2;

    for (size_t i = 0; i < bloom_m; ++i) {
        bloom[i] = b1[i] & b2[i];
    }

    return bloom_ones(bloom, bloom_m);
}
