
#include <assert.h>

#include "../main.h"

#include "ifstates.h"
#include "neighbors.h"
#include "traffic.h"


static void clear_old_traffic_counters(Traffic *traffic)
{
    assert(traffic != NULL);

    size_t idx = gstate.time_now % TRAFFIC_DURATION_SECONDS;
    uint32_t since = (gstate.time_now - traffic->updated_time);
    size_t n = MIN(since, TRAFFIC_DURATION_SECONDS);

    // clear old traffic measurement buckets
    for (size_t i = 0; i < n; ++i) {
        size_t j = (TRAFFIC_DURATION_SECONDS + idx + i + 1) % TRAFFIC_DURATION_SECONDS;
        traffic->in_bytes[j] = 0;
        traffic->out_bytes[j] = 0;
    }
}

void record_traffic(Traffic *traffic, uint32_t in_bytes, uint32_t out_bytes)
{
    clear_old_traffic_counters(traffic);

    size_t idx = gstate.time_now % TRAFFIC_DURATION_SECONDS;
    traffic->updated_time = gstate.time_now;
    traffic->in_bytes[idx] += out_bytes;
    traffic->out_bytes[idx] += in_bytes;
}

void record_traffic_by_addr(const Address *src, uint32_t out_bytes, uint32_t in_bytes)
{
    IFState *ifstate = ifstates_get(src);
    if (address_is_broadcast(src)) {
        record_traffic(&ifstate->broadcast_traffic, out_bytes, in_bytes);
        //Neighbor *neighbor = neighbors_get(src);
        //record_traffic(&neighbor->broadcast_traffic, out_bytes, in_bytes);
    } else {
        record_traffic(&ifstate->unicast_traffic, out_bytes, in_bytes);
        Neighbor *neighbor = neighbors_get(src);
        record_traffic(&neighbor->unicast_traffic, out_bytes, in_bytes);
    }
}
