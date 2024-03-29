
#include <string.h>
#include <stdlib.h>

#include "uthash.h"
#include "../utils.h"
#include "../log.h"
#include "../net.h"
#include "../main.h"


typedef struct {
    uint32_t src_id;
    uint16_t seq_num;
    uint64_t updated;
    UT_hash_handle hh;
} SeqNumCacheEntry;

static SeqNumCacheEntry *g_seqnum_cache = NULL;
static uint32_t g_seqnum_cache_timeout_sec = 30;

static void seqnum_cache_timeout()
{
    SeqNumCacheEntry *tmp;
    SeqNumCacheEntry *cur;

    HASH_ITER(hh, g_seqnum_cache, cur, tmp) {
        if ((cur->updated + g_seqnum_cache_timeout_sec * 1000) < gstate.time_now) {
            log_debug("timeout sequence number cache entry for id 0x%08x", cur->src_id);
            HASH_DEL(g_seqnum_cache, cur);
            free(cur);
        }
    }
}

int seqnum_cache_update(uint32_t src_id, uint16_t seq_num)
{
    SeqNumCacheEntry *cur;

    HASH_FIND(hh, g_seqnum_cache, &src_id, sizeof(uint32_t), cur);

    if (cur) {
        if (is_newer_seqnum(cur->seq_num, seq_num)) {
            cur->seq_num = seq_num;
            cur->updated = gstate.time_now;
            return 1; // new sequence number
        } else {
            return 0; // old sequence number, packet is a duplicate
        }
    }

    cur = (SeqNumCacheEntry*) malloc(sizeof(SeqNumCacheEntry));

    cur->src_id = src_id;
    cur->seq_num = seq_num;
    cur->updated = gstate.time_now;

    HASH_ADD(hh, g_seqnum_cache, src_id, sizeof(uint32_t), cur);

    return 1; // new sequence number, too
}

void seqnum_cache_init(uint32_t timeout)
{
    g_seqnum_cache_timeout_sec = timeout;
    net_add_handler(-1, &seqnum_cache_timeout);
}
