#ifndef _ROOT_STORAGE_0_NEIGHBORS_H_
#define _ROOT_STORAGE_0_NEIGHBORS_H_

#include <inttypes.h>
#include <stddef.h>

#include "packets.h"
#include "ranges.h"
#include "traffic.h"
#include "root.h"

#include "../ext/uthash.h"
#include "../address.h"


// for detecting connection breaks
typedef struct {
    Address address;

    // needed?
    //uint64_t packets_send_count;
    //uint64_t packets_send_time;

    uint8_t pinged;
    uint64_t time_created;
    uint64_t time_updated;

    //uint64_t root_store_to_others_received_time;
    bool is_child;
    uint64_t root_store_received_time;

    bool root_set;
    Root root;

    bool ranges_set;
    Ranges ranges;
    // neighbor is a child only if we received ranges recently and have not seen this node sending it do a different node
    //uint64_t ranges_updated;
    //uint64_t ranges_updated_next;
    // we should have the same for the root....

    // TODO: use
    Traffic unicast_traffic;
    Traffic broadcast_traffic;

    UT_hash_handle hh;
} Neighbor;

Neighbor *neighbors_all();
Neighbor *neighbors_find(const Address *addr);
Neighbor *neighbors_get(const Address *addr);
void neighbors_periodic();

#endif
