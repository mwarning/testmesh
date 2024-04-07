#ifndef _RANGES_0_H_
#define _RANGES_0_H_

/*
Compress/Decompress identifier ranges.

Compression:
1. sort and merge overlapping ranges
2. divide into list of short and long ranges, each prefixed by a varint length field
3. short ranges are stored as a sequence of single diff varint numbers,
   each decoded number represents a single identifier (a range of length 0)
4. long ranges are stored as a sequence of pairs of diff varint numbers,
   two decoded numbers represent a range

If the target space does not fit all data, then ranges are dropped and
merged to make more room available. Ranges that require more bytes to
store the others are dropped first.
*/

#include <stdbool.h>
#include <inttypes.h>

typedef struct {
    uint64_t from;
    uint64_t span;
} Range;

typedef struct {
    Range *data;
    size_t data_count;
    size_t data_capacity;
} Ranges;

void ranges_add(Ranges *ranges, uint64_t from, uint64_t span);
void ranges_add_all(Ranges *dst, const Ranges *src);

bool ranges_includes(const Ranges *ranges, uint64_t id);
const char *ranges_str(const Ranges *ranges);
uint64_t ranges_span(const Ranges *ranges);

void ranges_init(Ranges *ranges, size_t capacity_count);
void ranges_clear(Ranges *ranges);
void ranges_free(Ranges *ranges);
bool ranges_sanity_test();

int ranges_compress(uint8_t *packet, uint32_t packet_size, Ranges *ranges);
int ranges_decompress(Ranges *ranges, const uint8_t *packet, uint32_t packet_size);

#endif // _RANGES_0_H_
