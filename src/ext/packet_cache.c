
#include <string.h>
#include <stdlib.h>

#include "uthash.h"
#include "../utils.h"
#include "../log.h"
#include "../net.h"
#include "../main.h"


typedef struct PacketCacheEntry {
    uint32_t id; // destination id
    uint64_t updated;
    void* data;
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
        if ((cur->updated + g_packet_cache_timeout * 1000) < gstate.time_now) {
            log_debug("packet_cache_timeout() timeout packet cache entry for id 0x%08x", cur->id);
            packet_remove_entry(cur);
        }
    }
}

void packet_cache_get_and_remove(void *data_ret, size_t *data_length_ret, uint32_t id)
{
    PacketCacheEntry *cur;

    HASH_FIND(hh, g_packet_cache, &id, sizeof(uint32_t), cur);

    if (cur) {
        // copy entry
        *data_length_ret = cur->data_length;
        memcpy(data_ret, cur->data, cur->data_length);

        log_debug("packet_cache_get_and_remove() return after %s", str_since(cur->updated));

        // remove entry
        packet_remove_entry(cur);
    }
}

void packet_cache_add(uint32_t id, void *data, size_t data_length)
{
    PacketCacheEntry *e;
    bool is_new;

    // find existing entry
    HASH_FIND(hh, g_packet_cache, &id, sizeof(uint32_t), e);

    if (e) {
        free(e->data);
        is_new = false;
    } else {
        e = (PacketCacheEntry*) calloc(1, sizeof(PacketCacheEntry));
        is_new = true;
    }

    e->id = id;
    e->data = malloc(data_length);
    memcpy(e->data, data, data_length);
    e->data_length = data_length;
    e->updated = gstate.time_now;

    if (is_new) {
        HASH_ADD(hh, g_packet_cache, id, sizeof(uint32_t), e);
    } else {
        log_warning("packet_cache_add: drop stored packet for 0x%08x", id);
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
