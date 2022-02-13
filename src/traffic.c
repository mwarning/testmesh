#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "ext/uthash.h"
#include "utils.h"
#include "interfaces.h"
#include "log.h"
#include "traffic.h"


typedef struct {
    // hash map key
    Address addr;

    uint64_t bytes_out;
    uint64_t bytes_in;
    time_t updated;

    // for speed measurement
    uint64_t bytes_out_prev;
    uint64_t bytes_in_prev;
    time_t updated_prev;

    UT_hash_handle hh;
} Traffic;

// map of Address to Traffic
static Traffic *g_traffic = NULL;

// items in g_traffic
static uint32_t g_traffic_count = 0; // current
static uint32_t g_traffic_count_all = 0; // will never be decreased
static uint32_t g_traffic_count_max = 100;

// total traffic from outside (ignore key and hh)
static Traffic g_traffic_total = {0};


// forward declaration
static uint32_t traffic_fetch_subset(Traffic *ts[], uint32_t max_length, uint8_t ascending);

static void traffic_maintain_max_entries()
{
    if (g_traffic_count <= g_traffic_count_max) {
        return;
    }

    uint32_t remove_count = g_traffic_count - g_traffic_count_max;
    Traffic **ts = malloc(remove_count * sizeof(Traffic*));
    uint32_t found_count = traffic_fetch_subset(ts, remove_count, 1);

    // remove entries
    for (int i = 0; i < found_count; i++) {
        Traffic *cur;
        HASH_FIND(hh, g_traffic, &ts[i]->addr, sizeof(Address), cur);
        HASH_DEL(g_traffic, cur);
        free(cur);
        g_traffic_count -= 1;
    }

    free(ts);
}

static void traffic_add_bytes(const Address *addr, uint64_t bytes_in, uint64_t bytes_out)
{
    Traffic *cur;

    g_traffic_total.bytes_in += bytes_in;
    g_traffic_total.bytes_out += bytes_out;
    g_traffic_total.updated = gstate.time_now;

    if (g_traffic_total.updated != g_traffic_total.updated_prev) {
        g_traffic_total.bytes_in_prev = g_traffic_total.bytes_in;
        g_traffic_total.bytes_out_prev = g_traffic_total.bytes_out;
        g_traffic_total.updated_prev = g_traffic_total.updated;
    }

    HASH_FIND(hh, g_traffic, addr, sizeof(Address), cur);
    if (cur) {
        if (cur->updated != cur->updated_prev) {
            cur->bytes_in_prev = cur->bytes_in;
            cur->bytes_out_prev = cur->bytes_out;
            cur->updated_prev = cur->updated;
        }

        cur->bytes_in += bytes_in;
        cur->bytes_out += bytes_out;
        cur->updated = gstate.time_now;
    } else {
        traffic_maintain_max_entries();

        cur = (Traffic*) malloc(sizeof(Traffic));
        memcpy(&cur->addr, addr, sizeof(Address));
        cur->bytes_in = bytes_in;
        cur->bytes_out = bytes_out;
        cur->updated = gstate.time_now;
        cur->bytes_in_prev = 0;
        cur->bytes_out_prev = 0;
        cur->updated_prev = gstate.time_now;

        HASH_ADD(hh, g_traffic, addr, sizeof(Address), cur);

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
static uint32_t traffic_fetch_subset(Traffic *ts[], uint32_t max_length, uint8_t ascending)
{
    uint32_t current_length = 0;
    uint32_t low, high;
    Traffic *cur;
    Traffic *tmp;

    HASH_ITER(hh, g_traffic, cur, tmp) {
        low = 0;
        high = current_length;

        while (low < high) {
            uint32_t mid = (low + high) / 2;
            if (is_smaller(ts[mid], cur) ? ascending : !ascending) {
              low = mid + 1;
            } else {
              high = mid;
            }
        }

        uint32_t i = low;
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

    return current_length;
}

static const char *str_addr_ifname(const Address *addr)
{
    static char buf[16];
    uint32_t ifindex = 0;

    switch (addr->family) {
    case AF_INET:
        break;
    case AF_INET6:
        if (addr_is_link_local((struct sockaddr_storage*) addr)) {
            ifindex = addr->ip6.sin6_scope_id;
        }
        break;
    case AF_MAC:
        ifindex = addr->mac.ifindex;
    }

    snprintf(buf, sizeof(buf), "<%"PRIu32">", ifindex);

    if (ifindex == 0) {
        return buf;
    } else {
        const char *ifname = str_ifindex(ifindex);
        return ifname ? ifname : buf;
    }
}

static uint64_t speed_in(const Traffic *cur)
{
    if (cur->updated_prev >= cur->updated) {
        return 0; // invalid times
    } else {
        return (cur->bytes_in + cur->bytes_in_prev) / (cur->updated - cur->updated_prev);
    }
}

static uint64_t speed_out(const Traffic *cur)
{
    if (cur->updated_prev >= cur->updated) {
        return 0; // invalid times
    } else {
        return (cur->bytes_out + cur->bytes_out_prev) / (cur->updated - cur->updated_prev);
    }
}

void traffic_debug(FILE* out, int argc, char *argv[])
{
    uint32_t max_print;

    if (argc == 1) {
        max_print = g_traffic_count; // default
    } else if (argc == 2) {
        max_print = atoi(argv[1]);
    } else {
        fprintf(out, "invalid traffic statistics command\n");
        return;
    }

    uint32_t entries_count = MIN(g_traffic_count, max_print);
    Traffic **entries = malloc(entries_count * sizeof(Traffic*));

    uint32_t found_count = traffic_fetch_subset(entries, entries_count, 0);

    for (int i = 0; i < found_count; i++) {
        Traffic *cur = entries[i];
        fprintf(out, "%s/%s: in: %s (%s/s), out: %s (%s/s), %s ago\n",
            str_addr(&cur->addr),
            str_addr_ifname(&cur->addr),
            str_bytes(cur->bytes_in),
            str_bytes(speed_in(cur)),
            str_bytes(cur->bytes_out),
            str_bytes(speed_out(cur)),
            str_duration(cur->updated, gstate.time_now));
    }

    free(entries);

    fprintf(out, "%d addresses shown, %d overall, %d ever, %d max\n",
        entries_count, g_traffic_count, g_traffic_count_all, g_traffic_count_max);
    fprintf(out, "total: %s (%s/s) in, %s (%s/s) out\n",
        str_bytes(g_traffic_total.bytes_in),
        str_bytes(speed_in(&g_traffic_total)),
        str_bytes(g_traffic_total.bytes_out),
        str_bytes(speed_out(&g_traffic_total))
    );
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
