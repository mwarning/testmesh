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

static void traffic_add_bytes(const Address *addr, uint64_t bytes_in, uint64_t bytes_out)
{
    Traffic *cur;

    HASH_FIND(hh, g_traffic, addr, sizeof(Address), cur);
    if (cur) {
        cur->bytes_in += bytes_in;
        cur->bytes_out += bytes_out;
    } else {
        cur = (Traffic*) malloc(sizeof(Traffic));
        memcpy(&cur->addr, addr, sizeof(Address));
        cur->bytes_in = bytes_in;
        cur->bytes_out = bytes_out;
        cur->updated = gstate.time_now;

        HASH_ADD_INT(g_traffic, addr, cur);
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

void traffic_debug(FILE* out)
{
    int count = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;

    Traffic *cur;
    Traffic *tmp;
    HASH_ITER(hh, g_traffic, cur, tmp) {
        fprintf(out, "%s: %s %s %s ago\n",
            str_addr(&cur->addr),
            str_bytes(cur->bytes_in),
            str_bytes(cur->bytes_out),
            str_duration(cur->updated, gstate.time_now));
        bytes_in += cur->bytes_in;
        bytes_out += cur->bytes_out;
        count += 1;
    }

    fprintf(out, "%d addresses, %s %s \n", count, str_bytes(bytes_in), str_bytes(bytes_out));
}
