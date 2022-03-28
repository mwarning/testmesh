
#include <string.h>
#include <stdlib.h>

#include "uthash.h"
#include "../utils.h"
#include "../log.h"
#include "../net.h"
#include "../main.h"


typedef struct PacketCacheEntry {
    uint32_t id; // destination id
    time_t updated;
    uint8_t* data;
    size_t data_length;
    UT_hash_handle hh;
} PacketCacheEntry;


static PacketCacheEntry *g_packet_cache = NULL;
static uint32_t g_packet_cache_timeout = 5;

static void packet_remove_entry(PacketCacheEntry *cur)
{
    HASH_DEL(g_packet_cache, cur);
    free(cur->data);
    free(cur);
}

static void packet_cache_timeout()
{
    PacketCacheEntry *tmp;
    PacketCacheEntry *cur;

    HASH_ITER(hh, g_packet_cache, cur, tmp) {
        if ((cur->updated + g_packet_cache_timeout) < gstate.time_now) {
            log_debug("timeout packet cache entry for id 0x%08x", cur->id);
            packet_remove_entry(cur);
        }
    }
}

void packet_cache_get_and_remove(uint8_t *data_ret, size_t *data_length_ret, uint32_t id)
{
    PacketCacheEntry *cur;

    HASH_FIND(hh, g_packet_cache, &id, sizeof(uint32_t), cur);

    if (cur) {
        // copy entry
        *data_length_ret = cur->data_length;
        memcpy(data_ret, cur->data, cur->data_length);

        // remove entry
        packet_remove_entry(cur);
    }
}

void packet_cache_add(uint32_t id, uint8_t *data, size_t data_length)
{
    PacketCacheEntry *e;

    // find existing entry
    HASH_FIND(hh, g_packet_cache, &id, sizeof(uint32_t), e);

    int reuse = (e != NULL);

    if (reuse) {
        free(e->data);
    }

    e = (PacketCacheEntry*) calloc(1, sizeof(PacketCacheEntry));

    e->id = id;
    e->data = (uint8_t*) malloc(data_length);
    memcpy(e->data, data, data_length);
    e->data_length = data_length;
    e->updated = gstate.time_now;

    if (!reuse) {
        HASH_ADD(hh, g_packet_cache, id, sizeof(uint32_t), e);
    }
}

void packet_cache_init(uint32_t timeout)
{
    g_packet_cache_timeout = timeout;
    net_add_handler(-1, &packet_cache_timeout);
}

void packet_cache_clear()
{
    struct PacketCacheEntry *cur;
    struct PacketCacheEntry *tmp;

    // free all entries
    HASH_ITER(hh, g_packet_cache, cur, tmp) {
        packet_remove_entry(cur);
    }
}
