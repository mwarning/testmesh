#ifndef _BLOOM_H_
#define _BLOOM_H_

#include <inttypes.h>
#include <stdbool.h>

// Bloom Filter
#define BLOOM_M      8  // size of the bloom filter (in bytes)
#define BLOOM_K      2  // number of hash functions
#define BLOOM_LIMIT 50  // limit for the bloom filter (in percent)


#define BLOOM_BITSET(bv, idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define BLOOM_BITUNSET(bv, idx) (bv[(idx)/8U] &= ~(1U << ((idx)%8U)))
#define BLOOM_BITTEST(bv, idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))

// set BLOOM_K bits based on id
void bloom_init(void *bloom, uint64_t id);
void bloom_merge(void *bloom1, const void *bloom2);
void bloom_add(void *bloom, uint32_t id);
uint16_t bloom_ones(const void *bloom);
bool bloom_test(const void *bloom, uint32_t id);
void bloom_add(void *bloom, uint32_t id);
void bloom_delete(void *bloom, uint32_t id);

// count of same ones
uint16_t bloom_similar_ones(void *bloom1, void *bloom2);

char *str_bloom(const void *bloom);

#endif // _BLOOM_H_
