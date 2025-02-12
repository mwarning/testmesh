#ifndef _ROOT_STORAGE_0_IFSTATES_H_
#define _ROOT_STORAGE_0_IFSTATES_H_

#include <inttypes.h>
#include <stddef.h>

#include "traffic.h"

#include "../utils.h" // for Address type
#include "../ext/uthash.h"

// Per interface state. Removed/added only by interface_handler().
typedef struct {
    uint32_t ifindex;

    uint32_t neighbor_count;

    //enum INTERFACE_TYPE interface_type; // bluetooth, ethernet, lora

    //uint64_t send_broadcast_time;

    // We need to forward a broadcast (RREQ) if a neighbor uses us a source.
    //uint64_t recv_own_broadcast_time;
    Address recv_own_broadcast_address;

    uint64_t neighborhood_changed_time; // parent changed or neighbor added/removed
    uint64_t send_broadcast_time;
    uint64_t recv_own_broadcast_time;
    uint64_t recv_required_broadcast_time;

    // hm that should move to neighbor
    uint32_t ROOT_CREATE_send_interval_ms;

    // maybe put neighbors into her?

    // TODO: use
    Traffic unicast_traffic;
    Traffic broadcast_traffic;

    UT_hash_handle hh;
} IFState;

IFState *ifstates_all(); // TODO: remove

IFState *ifstates_find(const uint32_t ifindex);
void ifstates_remove(const uint32_t ifindex);

IFState *ifstates_create(const uint32_t ifindex);

// create non-existing entries
IFState *ifstates_get(const Address *address);

#endif
