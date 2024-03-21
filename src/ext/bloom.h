#ifndef _BLOOM_H_
#define _BLOOM_H_

#include <inttypes.h>
#include <stdbool.h>

#define BLOOM_BITSET(bv, idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define BLOOM_BITUNSET(bv, idx) (bv[(idx)/8U] &= ~(1U << ((idx)%8U)))
#define BLOOM_BITTEST(bv, idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))

// set BLOOM_K bits based on id
void bloom_init(void *bloom, uint64_t id, uint32_t bloom_m, uint32_t bloom_k);
void bloom_merge(void *bloom1, const void *bloom2, uint32_t bloom_m);
void bloom_add(void *bloom, uint32_t id, uint32_t bloom_m, uint32_t bloom_k);
uint16_t bloom_ones(const void *bloom, uint32_t bloom_m);
bool bloom_test(const void *bloom, uint32_t id, uint32_t bloom_m, uint32_t bloom_k);
void bloom_add(void *bloom, uint32_t id, uint32_t bloom_m, uint32_t bloom_k);
void bloom_delete(void *bloom, uint32_t id, uint32_t bloom_m, uint32_t bloom_k);

// count of same ones
uint16_t bloom_similar_ones(void *bloom1, void *bloom2, uint32_t bloom_m);

char *str_bloom(const void *bloom, uint32_t bloom_m);

#endif // _BLOOM_H_
