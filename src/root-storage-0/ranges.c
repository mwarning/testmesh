#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdio.h>

#include "ranges.h"

#define MIN(x, y) ((x) <= (y) ? (x) : (y))

static uint8_t write_count(uint64_t value)
{
    if (value < 0x80ULL) {
        return 1;
    } else if (value < 0x4000ULL) {
        return 2;
    } else if (value < 0x200000ULL) {
        return 3;
    } else if (value < 0x10000000ULL) {
        return 4;
    } else if (value < 0x800000000ULL) {
        return 5;
    } else if (value < 0x40000000000ULL) {
        return 6;
    } else if (value < 0x2000000000000ULL) {
        return 7;
    } else if (value < 0x100000000000000ULL) {
        return 8;
    } else {
        return 9;
    }
}

static int write_num(uint8_t *data, size_t data_len, uint64_t value)
{
    uint8_t bytes = write_count(value);

    if (data_len < bytes) {
        // not enough data
        return -1;
    }

    if (data == NULL) {
        // simulate only
        return bytes;
    }

    switch (bytes) {
    case 1:
        // 0xxxxxxx
        data[0] = value & 0xff;
        break;
    case 2:
        // 10xxxxxx
        data[0] = 0x80 + ((value >> 8) & ~0xC0);
        data[1] = (value >> 0) & 0xff;
        break;
    case 3:
        // 110xxxxx
        data[0] = 0xC0 + ((value >> 16) & ~0xE0);
        data[1] = (value >> 8) & 0xff;
        data[2] = (value >> 0) & 0xff;
        break;
    case 4:
        // 1110xxxx
        data[0] = 0xE0 + ((value >> 24) & ~0xF0);
        data[1] = (value >> 16) & 0xff;
        data[2] = (value >> 8) & 0xff;
        data[3] = (value >> 0) & 0xff;
        break;
    case 5:
        // 11110xxx
        data[0] = 0xF0 + ((value >> 32) & ~0xF8);
        data[1] = (value >> 24) & 0xff;
        data[2] = (value >> 16) & 0xff;
        data[3] = (value >> 8) & 0xff;
        data[4] = (value >> 0) & 0xff;
        break;
    case 6:
        // 111110xx
        data[0] = 0xF8 + ((value >> 40) & ~0xFC);
        data[1] = (value >> 32) & 0xff;
        data[2] = (value >> 24) & 0xff;
        data[3] = (value >> 16) & 0xff;
        data[4] = (value >> 8) & 0xff;
        data[5] = (value >> 0) & 0xff;
        break;
    case 7:
        // 1111110x
        data[0] = 0xFC + ((value >> 48) & ~0xFE);
        data[1] = (value >> 40) & 0xff;
        data[2] = (value >> 32) & 0xff;
        data[3] = (value >> 24) & 0xff;
        data[4] = (value >> 16) & 0xff;
        data[5] = (value >> 8) & 0xff;
        data[6] = (value >> 0) & 0xff;
        break;
    case 8:
        // 11111110
        data[0] = 0xFE;
        data[1] = (value >> 48) & 0xff;
        data[2] = (value >> 40) & 0xff;
        data[3] = (value >> 32) & 0xff;
        data[4] = (value >> 24) & 0xff;
        data[5] = (value >> 16) & 0xff;
        data[6] = (value >> 8) & 0xff;
        data[7] = (value >> 0) & 0xff;
    case 9:
        // 11111111
        data[0] = 0xFF;
        data[1] = (value >> 56) & 0xff;
        data[2] = (value >> 48) & 0xff;
        data[3] = (value >> 40) & 0xff;
        data[4] = (value >> 32) & 0xff;
        data[5] = (value >> 24) & 0xff;
        data[6] = (value >> 16) & 0xff;
        data[7] = (value >> 8) & 0xff;
        data[8] = (value >> 0) & 0xff;
        break;
    default:
        assert(0);
    }

    return bytes;
}

static int read_num(uint64_t *value, const uint8_t *data, size_t data_len)
{
    if (data_len < 1) {
        return -1;
    }

    uint8_t first = data[0];
    size_t bytes = 0;

    if ((first & 0x80) == 0x00) {
        // 0xxxxxxx
        *value = ((uint64_t) data[0]);
        bytes = 1;
    } else if ((first & 0xC0) == 0x80) {
        // 10xxxxxx
        if (data_len < 2) {
            return -1;
        }
        *value = ((((uint64_t) data[0]) & ~0xC0ULL) << 8)
            + (((uint64_t) data[1]) << 0);
        bytes = 2;
    } else if ((first & 0xE0) == 0xC0) {
        // 110xxxxx
        if (data_len < 3) {
            return -1;
        }
        *value = ((((uint64_t) data[0]) & ~0xE0ULL) << 16)
            + (((uint64_t) data[1]) << 8)
            + (((uint64_t) data[2]) << 0);
        bytes = 3;
    } else if ((first & 0xF0) == 0xE0) {
        // 1110xxxx
        if (data_len < 4) {
            return -1;
        }
        *value = ((((uint64_t) data[0]) & ~0xF0ULL) << 24)
            + (((uint64_t) data[1]) << 16)
            + (((uint64_t) data[2]) << 8)
            + (((uint64_t) data[3]) << 0);
        bytes = 4;
    } else if ((first & 0xF8) == 0xF0) {
        // 11110xxx
        if (data_len < 5) {
            return -1;
        }
        *value = ((((uint64_t) data[0]) & ~0xF8ULL) << 32)
            + (((uint64_t) data[1]) << 24)
            + (((uint64_t) data[2]) << 16)
            + (((uint64_t) data[3]) << 8)
            + (((uint64_t) data[4]) << 0);
        bytes = 5;
    } else if ((first & 0xFC) == 0xF8) {
        // 111110xx
        if (data_len < 6) {
            return -1;
        }
        *value = ((((uint64_t) data[0]) & ~0xFCULL) << 40)
            + (((uint64_t) data[1]) << 32)
            + (((uint64_t) data[2]) << 24)
            + (((uint64_t) data[3]) << 16)
            + (((uint64_t) data[4]) << 8)
            + (((uint64_t) data[5]) << 0);
        bytes = 6;
    } else if ((first & 0xFE) == 0xFC) {
        // 1111110x
        if (data_len < 7) {
            return -1;
        }
        *value = ((((uint64_t) data[0]) & ~0xFEULL) << 48)
            + (((uint64_t) data[1]) << 40)
            + (((uint64_t) data[2]) << 32)
            + (((uint64_t) data[3]) << 24)
            + (((uint64_t) data[4]) << 16)
            + (((uint64_t) data[5]) << 8)
            + (((uint64_t) data[6]) << 0);
        bytes = 7;
    } else if ((first & 0xFF) == 0xFE) {
        // 11111110
        if (data_len < 8) {
            return -1;
        }
        *value = (((uint64_t) data[1]) << 48)
            + (((uint64_t) data[2]) << 40)
            + (((uint64_t) data[3]) << 32)
            + (((uint64_t) data[4]) << 24)
            + (((uint64_t) data[5]) << 16)
            + (((uint64_t) data[6]) << 8)
            + (((uint64_t) data[7]) << 0);
        bytes = 8;
    } else if (((first & 0xFF) == 0xFF)) {
        // 11111111
        if (data_len < 9) {
            return -1;
        }
        *value = (((uint64_t) data[1]) << 48)
            + (((uint64_t) data[2]) << 40)
            + (((uint64_t) data[3]) << 32)
            + (((uint64_t) data[4]) << 24)
            + (((uint64_t) data[5]) << 16)
            + (((uint64_t) data[6]) << 8)
            + (((uint64_t) data[7]) << 0);
        bytes = 9;
    } else {
        // cannot happend unless we have a bug
        assert(0);
    }

    return bytes;
}

static int cmp_range_from(const void* _a, const void *_b)
{
    const Range *a = (const Range*) _a;
    const Range *b = (const Range*) _b;
    if (a->from > b->from) {
        return 1;
    } else if (a->from < b->from) {
        return -1;
    } else {
        return 0;
    }
}

static int cmp_range_span(const void* _a, const void *_b)
{
    const Range *a = (const Range*) _a;
    const Range *b = (const Range*) _b;
    if (a->span < b->span) {
        return 1;
    } else if (a->span > b->span) {
        return -1;
    } else {
        return 0;
    }
}

static void print_ranges(const char *context, Ranges *ranges)
{
    printf("########\n");
    printf("%s\n", context);
    for (int i = 0; i < ranges->data_count; ++i) {
        printf("[%03d] from %"PRIu64" + %"PRIu64"\n", i, ranges->data[i].from, ranges->data[i].span);
    }
    printf("ranges_count: %llu\n", ranges->data_count);
    printf("########\n");
}

static void print_ranges2(const char *context, Range *ranges_data, uint32_t ranges_count)
{
    Ranges ranges = {
        .data = ranges_data,
        .data_count = ranges_count,
        .data_capacity = 0,
    };
    print_ranges(context, &ranges);
}

static int compress_big_ranges(uint8_t *packet, uint32_t packet_size, Range *ranges, uint32_t ranges_count)
{
    //printf("compress_big_ranges start: ranges_count: %d\n", (int) ranges_count);

    size_t offset = 0;

    // write number of big ranges
    int bytes1 = write_num(packet ? &packet[offset] : NULL, packet_size - offset, ranges_count);
    if (bytes1 < 0) {
        return -1;
    }
    offset += bytes1;

    uint32_t ranges_written = 0;
    uint64_t prev = 0;
    for (size_t i = 0; i < ranges_count; ++i) {
        Range *r = &ranges[i];
        //printf("%"PRIu64" > %"PRIu64"\n", r->from, prev);
        assert(r->from > prev);
        uint64_t diff1 = r->from - prev;
        uint64_t diff2 = r->span;

        int bytes1 = write_num(packet ? &packet[offset] : NULL, packet_size - offset, diff1);
        if (bytes1 < 0) {
            return -1;
        }

        int bytes2 = write_num(packet ? &packet[offset + bytes1] : NULL, packet_size - offset - bytes1, diff2);
        if (bytes2 < 0) {
            return -1;
        }

        //printf("diff1: %"PRIu64", diff2: %"PRIu64", bytes1: %d, bytes2: %d\n", diff1, diff2, (int) bytes1, (int) bytes2);

        offset += bytes1 + bytes2;
        ranges_written += 1;
        prev = r->from + r->span;
    }

    //printf("compress_big_ranges end; ranges_written: %d, offset: %d\n", (int) ranges_written, (int) offset);
    return offset;
}

static uint32_t compress_small_ranges(uint8_t *packet, uint32_t packet_size, Range *ranges, uint32_t ranges_count)
{
    //printf("compress_small_ranges start\n");

    size_t offset = 0;

    // write number of big ranges
    int bytes1 = write_num(packet ? &packet[offset] : NULL, packet_size - offset, ranges_count);
    if (bytes1 < 0) {
        return -1;
    }
    offset += bytes1;

    uint32_t ranges_written = 0;
    uint64_t prev = 0;
    for (size_t i = 0; i < ranges_count; ++i) {
        Range *r = &ranges[i];
        uint64_t diff = r->from - prev;

        int bytes = write_num(packet ? &packet[offset] : NULL, packet_size - offset, diff);
        if (bytes < 0) {
            break;
        }
        offset += bytes;
        //printf("from: %"PRIu64", diff: %"PRIu64", bytes: %d\n", r->from, diff, (int) bytes);

        //printf("compress_small_ranges %d, %d\n", i, (int) r->span);
        for (uint64_t j = 0; j < r->span; ++j) {
            diff = 1;
            int bytes = write_num(packet ? &packet[offset] : NULL, packet_size - offset, diff);
            if (bytes < 0) {
                break;
            }
            offset += bytes;
            //printf("diff: %"PRIu64", bytes: %d\n", diff, (int) bytes);
        }

        ranges_written += 1;
        prev = r->from + r->span;
    }

    //print_ranges2("compress_small_ranges", ranges, ranges_count);

    //printf("compress_small_ranges end; ranges_written: %d, offset: %d\n", (int) ranges_written, (int) offset);
    return offset;
}

static int decompress_small_ranges(Ranges *ranges, const uint8_t *packet, uint32_t packet_size)
{
    //printf("decompress_small_ranges: packet_size: %d\n", (int) packet_size);

    size_t offset = 0;
    uint64_t ranges_count = 0;

    int bytes0 = read_num(&ranges_count, &packet[offset], packet_size - offset);
    if (bytes0 <= 0 || ranges_count >= UINT16_MAX) {
        return -1;
    }
    offset += bytes0;

    //printf("ranges_count: %"PRIu64"\n",  ranges_count);

    uint64_t prev_end = 0;

    uint32_t i = 0;
    while (offset < packet_size) {
        uint64_t diff = 0;
        int bytes1 = read_num(&diff, &packet[offset], packet_size - offset);
        if (bytes1 == -1) {
            return -1;
        }

        offset += bytes1;

        if (i == 0) {
            ranges_add(ranges, prev_end + diff, 0);
            i += 1;
        } else {
            if (diff == 0) {
                // ignore, we would two identical ranges
                continue;
            } else if (diff == 1) {
                ranges->data[ranges->data_count - 1].span += 1;
            } else {
                ranges_add(ranges, prev_end + diff, 0);
                i += 1;
            }
        }

        prev_end += diff;
    }

    if (i != ranges_count) {
        return -1;
    }

    //printf("decompress_small_ranges: %d ranges, offset: %d\n", (int) ranges->data_count, (int) offset);

    return offset;
}

static int decompress_big_ranges(Ranges *ranges, const uint8_t *packet, uint32_t packet_size)
{
    //printf("packet_size: %d\n", (int) packet_size);
    size_t offset = 0;
    uint64_t ranges_count = 0;

    int bytes0 = read_num(&ranges_count, &packet[offset], packet_size - offset);
    if (bytes0 <= 0 || ranges_count >= UINT16_MAX) {
        return -1;
    }
    offset += bytes0;

    uint64_t prev_end = 0;
    uint32_t i = 0;
    while (offset < packet_size && i < ranges_count) {
        uint64_t diff = 0;
        int bytes1 = read_num(&diff, &packet[offset], packet_size - offset);
        if (bytes1 == -1) {
            break;
        }
        offset += bytes1;

        //printf("decompress_big_ranges: from: %"PRIu64"\n", from);

        uint64_t span = 0;
        int bytes2 = read_num(&span, &packet[offset], packet_size - offset);
        if (bytes2 == -1) {
            break;
        }
        offset += bytes2;
        //printf("decompress_big_ranges: span: %"PRIu64"\n", span);

        ranges_add(ranges, prev_end + diff, span);

        prev_end += diff + span;
        i += 1;
    }

    if (i != ranges_count) {
        return -1;
    }

    //print_ranges("decompress_big_ranges:", ranges_ret, ranges_count);
    //printf("decompress_big_ranges: %d ranges, offset: %d\n", (int) ranges_count, (int) offset);

    //*ranges_count_ret += ranges_count;
    return offset;
}

static void remove_range(Ranges *ranges, size_t index)
{
    memmove(&ranges->data[index], &ranges->data[index+1], (ranges->data_count - index) * sizeof(Range));
    ranges->data_count -= 1;
}

static uint32_t merge_ranges(Ranges *ranges, uint64_t distance)
{
    qsort(ranges->data, ranges->data_count, sizeof(Range), &cmp_range_from);

    for (size_t i = 1; i < ranges->data_count; ++i) {
        while (i < ranges->data_count) {
            Range *r0 = &ranges->data[i-1];
            Range *r1 = &ranges->data[i];
            if ((r0->from + r0->span + distance) >= r1->from) {
                uint64_t new_end = r1->from + r1->span;
                r0->span = new_end - r0->from;
                // remove merged range
                remove_range(ranges, i);
            } else {
                break;
            }
        }
    }

    return ranges->data_count;
}

static uint64_t get_range_min_diff(const Ranges *ranges, size_t index)
{
    //size_t count = ranges->data_count;
    Range *rs = ranges->data;
    const Range *r = &rs[index];

    if (index == 0) {
        // first item
        //printf("index is zero: %"PRIu64" - %"PRIu64"\n", ranges[index+1].from, r->from);
        return rs[index+1].from - (r->from + r->span);
    } else if (index == (ranges->data_count - 1)) {
        // last item
        return r->from - (rs[index-1].from + rs[index-1].span);
    } else {
        uint64_t diff_prev = r->from - (rs[index-1].from + rs[index-1].span);
        uint64_t diff_next = rs[index+1].from - (r->from + r->span);
        return MIN(diff_prev, diff_next);
    }
}

// drop range that has the biggest difference to it's neihgbors
static uint32_t drop_ranges(Ranges *ranges, uint64_t distance_TODO)
{
    if (ranges->data_count == 0) {
        return 0;
    }

    qsort(ranges->data, ranges->data_count, sizeof(Range), &cmp_range_from);

    uint64_t diff_max = 0;
    size_t diff_idx = UINT32_MAX;

    for (size_t i = 0; i < ranges->data_count; ++i) {
        uint64_t diff = get_range_min_diff(ranges, i);
        if (diff > diff_max) {
            diff_max = diff;
            diff_idx = i;
        }
    }

    if (diff_idx != UINT32_MAX) {
        remove_range(ranges, diff_idx);
    }

    return ranges->data_count;
}

int ranges_decompress(Ranges *ranges, const uint8_t *packet, uint32_t packet_size)
{
    //printf("ranges_decompress start\n");
    size_t offset = 0;
    uint32_t ranges_count = 0;

    int bytes1 = decompress_big_ranges(ranges, &packet[offset], packet_size - offset);
    if (bytes1 == -1) {
        return -1;
    }
    offset += bytes1;

    int bytes2 = decompress_small_ranges(ranges, &packet[offset], packet_size - offset);
    if (bytes2 == -1) {
        return -1;
    }
    offset += bytes2;

    // sort so we can compare the ranges better for testing
    qsort(ranges->data, ranges->data_count, sizeof(Range), &cmp_range_from);

    return offset;
}

static int compress(uint8_t *packet, uint32_t packet_size, Ranges* ranges)
{
    qsort(ranges->data, ranges->data_count, sizeof(Range), &cmp_range_span);

    uint32_t border_count = ranges->data_count;
    for (uint32_t i = 0; i < border_count; ++i) {
        if (ranges->data[i].span <= 2) {
            border_count = i;
            break;
        }
    }

    Range *big_ranges = ranges->data;
    uint32_t big_ranges_count = border_count;

    Range *small_ranges = ranges->data + border_count;
    uint32_t small_ranges_count = ranges->data_count - border_count;

    // sort big and small ranges separately
    qsort(big_ranges, big_ranges_count, sizeof(Range), &cmp_range_from);
    qsort(small_ranges, small_ranges_count, sizeof(Range), &cmp_range_from);

    size_t offset = 0;

    int bytes_written_big = compress_big_ranges(packet ? &packet[offset] : NULL, packet_size - offset, big_ranges, big_ranges_count);
    if (bytes_written_big == -1) {
        return -1;
    }
    offset += bytes_written_big;

    int bytes_written_small = compress_small_ranges(packet ? &packet[offset] : NULL, packet_size - offset, small_ranges, small_ranges_count);
    if (bytes_written_small == -1) {
        return -1;
    }
    offset += bytes_written_small;

    // undo changes?
    qsort(ranges->data, ranges->data_count, sizeof(Range), &cmp_range_from);

    //printf("compress; border_count: %d, bytes_written_big: %d, big_ranges_count: %d, bytes_written_small: %d, small_ranges_count: %d\n",
    //    (int) border_count, (int) bytes_written_big, (int) big_ranges_count, (int) bytes_written_small, (int) small_ranges_count);

    return offset;
}

// calulate the amount of bytes saved when we remove the item with the biggest min_diff
static int drop_ranges_estimate_bytes_saved(size_t packet_size, const Ranges *ranges, uint64_t merge_distance)
{
    //printf("# drop_ranges_estimate_bytes_saved begin\n");
    if (ranges->data_count == 0) {
        return 0;
    }

    // create copy
    Ranges ranges_new;
    ranges_init(&ranges_new);
    ranges_add_all(&ranges_new, ranges);

    // shrink copy
    drop_ranges(&ranges_new, merge_distance);

    int written_bytes = compress(NULL, UINT32_MAX, &ranges_new);
    ranges_free(&ranges_new);

    //printf("# drop_ranges_estimate_bytes_saved end\n");
    return written_bytes;
}

static int merge_ranges_estimate_bytes_saved(size_t packet_size, const Ranges *ranges, uint64_t merge_distance)
{
    //printf("# merge_ranges_estimate_bytes_saved begin\n");
    if (ranges->data_count == 0) {
        return 0;
    }

    // create copy
    Ranges ranges_new;
    ranges_init(&ranges_new);
    ranges_add_all(&ranges_new, ranges);

    // shrink copy
    merge_ranges(&ranges_new, merge_distance);

    int bytes_written = compress(NULL, UINT32_MAX, &ranges_new);
    ranges_free(&ranges_new);

    //printf("# merge_ranges_estimate_bytes_saved end\n");
    return bytes_written;
}

int ranges_compress(uint8_t *packet, size_t packet_size, Ranges *ranges)
{
    // make sure that we have no overlapping ranges
    merge_ranges(ranges, 0);

    //print_ranges("ranges_compress:", ranges);

    uint64_t distance = 1;

    // calculate the size if we had enough storage
    uint32_t current_size = compress(NULL, UINT32_MAX, ranges);
    printf("current_size: %d\n", current_size);

    while (current_size > packet_size) {
        // calculate next step
        int drop_bytes = drop_ranges_estimate_bytes_saved(packet_size, ranges, distance);
        int merge_bytes = merge_ranges_estimate_bytes_saved(packet_size, ranges, distance);

        printf("distance: %"PRIu64", drop ranges: improve by %d bytes, merge ranges: improve by %d bytes ",
                distance, current_size - drop_bytes, current_size - merge_bytes);

        if (drop_bytes >= 0 && ((merge_bytes >= 0 && drop_bytes < merge_bytes) || merge_bytes < 0)) {
            printf("=> drop_ranges\n");
            drop_ranges(ranges, distance);
            current_size = drop_bytes;
        } else if (merge_bytes >= 0) {
            printf("=> merge_ranges\n");
            merge_ranges(ranges, distance);
            current_size = merge_bytes;
        } else {
            printf("=> increase distance\n");
        }

        distance *= 2;
    }

    // compress ranges
    int bytes = compress(packet, packet_size, ranges);
    printf("bytes: %d, current_size: %d, packet_size: %d\n", bytes, current_size, packet_size);
    assert(bytes == current_size);
    return bytes;
}

const char *ranges_str(const Ranges *ranges)
{
    static char strdurationbuf[4][256];
    static size_t strdurationbuf_i = 0;
    char *buf = strdurationbuf[++strdurationbuf_i % 4];

    buf[0] = 0;
    int rc;
    const char *fmt;
    for (size_t i = 0, written = 0; i < ranges->data_count; ++i) {
        Range *range = &ranges->data[i];
        fmt = (written > 0) ? ", 0x%"PRIx64"+0x%"PRIx64"" : "0x%"PRIx64"+0x%"PRIx64"";
        rc = snprintf(&buf[written], sizeof(strdurationbuf[0]) - written, fmt, range->from, range->span);
        if (rc > 0) {
            written += rc;
        } else {
            snprintf(&buf[written], sizeof(strdurationbuf[0]) - written, "...");
            break;
        }
    }

    return buf;
}

bool ranges_includes(const Ranges *ranges, uint64_t id)
{
    for (size_t i = 0; i < ranges->data_count; ++i) {
        const Range *r = &ranges->data[i]; 
        if (id >= r->from && id < r->from + r->span) {
            return true;
        }
    }
    return false;
}

void ranges_init(Ranges *ranges)
{
    ranges->data = NULL;
    ranges->data_count = 0;
    ranges->data_capacity = 0;
}

void ranges_clear(Ranges *ranges)
{
    ranges->data_count = 0;
}

void ranges_free(Ranges *ranges)
{
    if (ranges->data) {
        free(ranges->data);
    }
    ranges_init(ranges);
}

void ranges_add(Ranges *ranges, uint64_t from, uint64_t span)
{
    if (ranges->data) {
        if (ranges->data_capacity == ranges->data_count) {
            ranges->data_capacity *= 2;
            ranges->data = (Range*) realloc(ranges->data, sizeof(Range) * ranges->data_capacity);
        }
    } else {
        ranges->data_count = 0;
        ranges->data_capacity = 1;
        ranges->data = (Range*) malloc(sizeof(Range) * ranges->data_capacity);
    }

    ranges->data[ranges->data_count] = (Range) {
        .from = from,
        .span = span,
    };
    ranges->data_count += 1;
}

void ranges_add_all(Ranges *dst, const Ranges *src)
{
    for (size_t i = 0; i < src->data_count; ++i) {
        ranges_add(dst, src->data[i].from, src->data[i].span);
    }
}
