#ifndef _RANGES_0_H_
#define _RANGES_0_H_

typedef struct {
    uint64_t from;
    uint64_t span;
} Range;

typedef struct {
    Range *data;
    size_t data_count;
    size_t data_capacity;
} Ranges;

uint32_t merge_ranges(Ranges *ranges, uint64_t distance);

void ranges_add(Ranges *ranges, uint64_t from, uint64_t span);
void ranges_add_all(Ranges *dst, const Ranges *src);

bool ranges_includes(const Ranges *ranges, uint64_t id);
const char *ranges_str(const Ranges *ranges);

void ranges_init(Ranges *ranges);
void ranges_clear(Ranges *ranges);
void ranges_free(Ranges *ranges);

int ranges_compress(uint8_t *packet, size_t packet_size, Ranges *ranges);
int ranges_decompress(Ranges *ranges, const uint8_t *packet, uint32_t packet_size);

#endif // _RANGES_0_H_
