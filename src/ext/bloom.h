#ifndef _BLOOM_H_
#define _BLOOM_H_

#include <inttypes.h>

// Bloom Filter
#define BLOOM_M      8  // size of the bloom filter (in bytes)
#define BLOOM_K      2  // number of hash functions
#define BLOOM_LIMIT 50  // limit for the bloom filter (in percent)


#define BLOOM_BITSET(bv, idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define BLOOM_BITUNSET(bv, idx) (bv[(idx)/8U] &= ~(1U << ((idx)%8U)))
#define BLOOM_BITTEST(bv, idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))

// set BLOOM_K bits based on id
void bloom_init(uint8_t *bloom, uint64_t id);
void bloom_merge(uint8_t *bloom1, const uint8_t *bloom2);
void bloom_add(uint8_t *bloom, uint32_t id);
uint16_t bloom_ones(const uint8_t *bloom);
uint8_t bloom_test(const uint8_t *bloom, uint32_t id);
void bloom_add(uint8_t *bloom, uint32_t id);
void bloom_delete(uint8_t *bloom, uint32_t id);
uint16_t bloom_similar(uint8_t *bloom1, uint8_t *bloom2);

char *str_bloom(const uint8_t *bloom);

#endif // _BLOOM_H_
