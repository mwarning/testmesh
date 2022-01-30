
#include <string.h>
#include <stdlib.h>

#include "utlist.h"
#include "../utils.h"
#include "../log.h"
#include "../net.h"
#include "../main.h"


typedef struct NeighborCacheEntry {
    uint32_t id;
    Address addr;
    time_t updated;
    struct NeighborCacheEntry *next;
} NeighborCacheEntry;

static NeighborCacheEntry *g_neighbor_cache = NULL;
static uint32_t g_neighbor_cache_timeout = 5;

static void neighbor_cache_timeout()
{
    NeighborCacheEntry *tmp;
    NeighborCacheEntry *cur;

    LL_FOREACH_SAFE(g_neighbor_cache, cur, tmp) {
        if ((cur->updated + g_neighbor_cache_timeout) < gstate.time_now) {
            log_debug("timeout neighbor cache entry for id 0x%08x", cur->id);
            LL_DELETE(g_neighbor_cache, cur);
        }
    }
}

const Address *neighbor_cache_lookup(uint32_t id)
{
    NeighborCacheEntry *cur;

    LL_FOREACH(g_neighbor_cache, cur) {
        if (cur->id == id) {
            return &cur->addr;
        }
    }

    return NULL;
}

void neighbor_cache_add(uint32_t id, const Address *addr)
{
    NeighborCacheEntry *e;

    e = (NeighborCacheEntry*) malloc(sizeof(NeighborCacheEntry));

    e->id = id;
    memcpy(&e->addr, addr, sizeof(Address));
    e->updated = gstate.time_now;

    LL_PREPEND(g_neighbor_cache, e);
}

void neighbor_cache_init(uint32_t timeout)
{
    g_neighbor_cache_timeout = timeout;
    net_add_handler(-1, &neighbor_cache_timeout);
}
