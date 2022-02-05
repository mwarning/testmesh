#include <string.h>

#include "ext/uthash.h"
#include "utils.h"
#include "log.h"
#include "traffic.h"

typedef struct {
    Address addr;
    uint64_t bytes_out;
    uint64_t bytes_in;
    time_t updated;
    UT_hash_handle hh;
} Traffic;

static Traffic *g_traffic = NULL;
static int g_traffic_count = 0;
static int g_traffic_count_all = 0; // will never be decreased
static int g_traffic_count_max = 100; // configuration
static uint64_t g_bytes_total_in = 0;
static uint64_t g_bytes_total_out = 0;


static void traffic_maintain_max_entries()
{
    Address addrs[10];
    uint64_t bytes[10];
    time_t updates[10];
    int count;
    Traffic *cur;
    Traffic *tmp;

    // remove entries in up to 10 elements at a time
    while (g_traffic_count > g_traffic_count_max) {
        count = 0;
        HASH_ITER(hh, g_traffic, cur, tmp) {
            uint64_t sum = cur->bytes_out + cur->bytes_in;
            if (count < 10) {
                addrs[count] = cur->addr;
                bytes[count] = sum;
                updates[count] = cur->updated;
                count += 1;
            } else {
                for (int i = 0; i < 10; i++) {
                    if (sum > bytes[i] || (sum == bytes[i] && updates[i] < cur->updated)) {
                        addrs[i] = cur->addr;
                        bytes[i] = sum;
                        updates[i] = cur->updated;
                        break;
                    }
                }
            }
        }

        // remove entries
        for (int i = 0; i < count; i++) {
            HASH_FIND(hh, g_traffic, &addrs[i], sizeof(Address), cur);
            HASH_DEL(g_traffic, cur);
            free(cur);
            g_traffic_count -= 1;
        }
    }
}

static void traffic_add_bytes(const Address *addr, uint64_t bytes_in, uint64_t bytes_out)
{
    Traffic *cur;

    g_bytes_total_in += bytes_in;
    g_bytes_total_out += bytes_out;

    HASH_FIND(hh, g_traffic, addr, sizeof(Address), cur);
    if (cur) {
        cur->bytes_in += bytes_in;
        cur->bytes_out += bytes_out;
    } else {
        traffic_maintain_max_entries();

        cur = (Traffic*) malloc(sizeof(Traffic));
        memcpy(&cur->addr, addr, sizeof(Address));
        cur->bytes_in = bytes_in;
        cur->bytes_out = bytes_out;
        cur->updated = gstate.time_now;

        HASH_ADD_INT(g_traffic, addr, cur);

        g_traffic_count += 1;
        g_traffic_count_all += 1;
    }
}

void traffic_add_bytes_out(const Address *addr, uint64_t bytes)
{
    traffic_add_bytes(addr, 0, bytes);
}

void traffic_add_bytes_in(const Address *addr, uint64_t bytes)
{
    traffic_add_bytes(addr, bytes, 0);
}

static int is_smaller(Traffic *a, Traffic *b)
{
    uint64_t a_sum = a->bytes_out + a->bytes_in;
    uint64_t b_sum = b->bytes_out + b->bytes_in;
    return (a_sum < b_sum) || (a_sum == b_sum && a->updated < b->updated);
}

// get sorted list of traffic entries
static void traffic_fetch_subset(Traffic *ts[], int max_length)
{
    int current_length = 0;
    int low, high;
    Traffic *cur;
    Traffic *tmp;

    HASH_ITER(hh, g_traffic, cur, tmp) {
        low = 0;
        high = current_length;

        while (low < high) {
            int mid = (low + high) / 2;
            if (!is_smaller(ts[mid], cur)) {
              low = mid + 1;
            } else {
              high = mid;
            }
        }

        int i = low;
        if (i >= max_length) {
            continue;
        } else if (i < current_length) {
            if (current_length == max_length) {
              memcpy(&ts[i+1], &ts[i], (current_length - i - 1) * sizeof(Traffic*));
              ts[i] = cur;
            } else {
              memcpy(&ts[i+1], &ts[i], (current_length - i) * sizeof(Traffic*));
              ts[i] = cur;
              current_length += 1;
            }
        } else {
          ts[i] = cur;
          current_length += 1;
        }
    }
}

void traffic_debug(FILE* out, int argc, char *argv[])
{
    uint32_t max_print;

    if (!gstate.traffic_stats_enabled) {
        fprintf(out, "traffic statistics are disabled\n");
        return;
    }

    if (argc == 1) {
        max_print = g_traffic_count; // default
    } else if (argc == 2) {
        max_print = atoi(argv[1]);
    } else {
        fprintf(out, "invalid traffic statistics command\n");
        return;
    }

    uint32_t entries_count = MAX(g_traffic_count, max_print);
    Traffic **entries = malloc(entries_count * sizeof(Traffic*));

    traffic_fetch_subset(entries, entries_count);

    for (int i = 0; i < entries_count; i++) {
        Traffic *cur = entries[i];
        fprintf(out, "%s: in: %s, out: %s, %s ago\n",
            str_addr(&cur->addr),
            str_bytes(cur->bytes_in),
            str_bytes(cur->bytes_out),
            str_duration(cur->updated, gstate.time_now));
    }

    free(entries);

    fprintf(out, "%d addresses shown (%d overall, %d ever, %d max)\n",
        entries_count, g_traffic_count, g_traffic_count_all, g_traffic_count_max);
    fprintf(out, "traffic: %s in, %s out\n",
        str_bytes(g_bytes_total_in), str_bytes(g_bytes_total_out));
}

void traffic_cleanup()
{
    Traffic *cur;
    Traffic *tmp;
    HASH_ITER(hh, g_traffic, cur, tmp) {
        HASH_DEL(g_traffic, cur);
        free(cur);
    }
}