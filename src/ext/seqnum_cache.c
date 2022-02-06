
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
    time_t updated;
    UT_hash_handle hh;
} SeqNumCacheEntry;

static SeqNumCacheEntry *g_seqnum_cache = NULL;
static uint32_t g_seqnum_cache_timeout_sec = 30;

static void seqnum_cache_timeout()
{
    SeqNumCacheEntry *tmp;
    SeqNumCacheEntry *cur;

    HASH_ITER(hh, g_seqnum_cache, cur, tmp) {
        if ((cur->updated + g_seqnum_cache_timeout_sec) < gstate.time_now) {
            log_debug("timeout sequence number cache entry for id 0x%08x", cur->src_id);
            HASH_DEL(g_seqnum_cache, cur);
            free(cur);
        }
    }
}

// returns |new - cur| < UINT16_MAX/2
static int is_newer_seqnum(uint16_t cur, uint16_t new)
{
    if (cur >= new) {
        return (cur - new) > 0x7fff;
    } else {
        return (new - cur) < 0x7fff;
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
            return 1;
        } else {
            return 0;
        }
    }

    cur = (SeqNumCacheEntry*) malloc(sizeof(SeqNumCacheEntry));

    cur->src_id = src_id;
    cur->seq_num = seq_num;
    cur->updated = gstate.time_now;

    HASH_ADD_INT(g_seqnum_cache, src_id, cur);

    return 1;
}

void seqnum_cache_init(uint32_t timeout)
{
    g_seqnum_cache_timeout_sec = timeout;
    net_add_handler(-1, &seqnum_cache_timeout);
}
