
#include <string.h>
#include <stdlib.h>

//#include "../utlist.h"
#include "../uthash.h"
#include "../utils.h"
#include "../log.h"
#include "../net.h"
#include "../main.h"


typedef struct /*PacketCacheEntry_*/ {
    uint32_t id; // destination id
    time_t updated;
    uint8_t* data;
    size_t data_length;
    //struct PacketCacheEntry_ *next;
    UT_hash_handle hh;
} PacketCacheEntry;


static PacketCacheEntry *g_packet_cache = NULL;
static uint32_t g_packet_cache_timeout = 5;

static void packet_cache_timeout()
{
    PacketCacheEntry *tmp;
    PacketCacheEntry *cur;

    HASH_ITER(hh, g_packet_cache, cur, tmp) {
    //LL_FOREACH_SAFE(g_packet_cache, cur, tmp) {
        if ((cur->updated + g_packet_cache_timeout) < gstate.time_now) {
            log_debug("timeout packet cache entry for id 0x%08x", cur->id);
            HASH_DEL(g_packet_cache, cur);
            //LL_DELETE(g_packet_cache, cur);
            free(cur->data);
            free(cur);
        }
    }
}

void packet_cache_get_and_remove(uint8_t *data_ret, size_t *data_length_ret, uint32_t id)
{
    //PacketCacheEntry *tmp;
    PacketCacheEntry *cur = NULL;

    HASH_FIND_INT(g_packet_cache, &id, cur);

    //LL_FOREACH_SAFE(g_packet_cache, cur, tmp) {
        //if (cur->id == id) {
        if (cur) {
            *data_length_ret = cur->data_length;
            memcpy(data_ret, cur->data, cur->data_length);
            //LL_DELETE(g_packet_cache, cur);
            HASH_DEL(g_packet_cache, cur);
            free(cur->data);
            free(cur);
            return;
        }
    //}
}

void packet_cache_add(uint32_t id, uint8_t *data, size_t data_length)
{
    PacketCacheEntry *e = NULL;

    // remove existing entry
    HASH_FIND_INT(g_packet_cache, &id, e);

    if (e) {
        free(e->data);
        free(e);
    }

//TODO: try HASH_REPLACE

    e = (PacketCacheEntry*) malloc(sizeof(PacketCacheEntry));

    e->id = id;
    e->data = (uint8_t*) malloc(data_length);

    memcpy(e->data, data, data_length);
    e->data_length = data_length;
    e->updated = gstate.time_now;

    HASH_ADD_INT(g_packet_cache, id, e);
    //LL_PREPEND(g_packet_cache, e);
}

void packet_cache_init(uint32_t timeout)
{
    g_packet_cache_timeout = timeout;
    net_add_handler(-1, &packet_cache_timeout);
}
