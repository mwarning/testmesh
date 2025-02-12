#include "../main.h"
#include "../log.h"

#include "ifstates.h"
#include "tree.h"
#include "nodes.h"
#include "neighbors.h"


static Neighbor *g_neighbors = NULL; // key includes the interface number (ifindex)


Neighbor *neighbors_all()
{
	return g_neighbors;
}

Neighbor *neighbors_find(const Address *addr)
{
    Neighbor *neighbor = NULL;
    HASH_FIND(hh, g_neighbors, addr, sizeof(Address), neighbor);
    return neighbor;
}

static void neighbors_added(const Neighbor *neighbor)
{
    IFState *ifstate = ifstates_get(&neighbor->address);
    ifstate->neighborhood_changed_time = gstate.time_now;
    ifstate->neighbor_count += 1;
}

Neighbor *neighbors_get(const Address *addr)
{
    Neighbor *neighbor = neighbors_find(addr);
    if (neighbor == NULL) {
        // add new entry
        neighbor = (Neighbor*) calloc(1, sizeof(Neighbor));
        neighbor->time_created = gstate.time_now;
        memcpy(&neighbor->address, addr, sizeof(Address));
        HASH_ADD(hh, g_neighbors, address, sizeof(Address), neighbor);

        // trigger event
        neighbors_added(neighbor);
    }
    return neighbor;
}

static void neighbors_removed(const Neighbor *neighbor)
{
    log_debug("neighbors_removed() %s", str_addr(&neighbor->address));

    // make sure that the node is removed as well
    nodes_remove_next_hop_addr(&neighbor->address);

    IFState *ifstate = ifstates_get(&neighbor->address);
    ifstate->neighborhood_changed_time = gstate.time_now;
    ifstate->neighbor_count -= 1;

    tree_neighbor_removed(neighbor);

/*
    if (address_equal(&neighbor->recv_own_broadcast_address)) {
        memset(&neighbor->recv_own_broadcast_address, 0, sizeof(Address));
        neighbor->recv_own_broadcast_time = 0;
    }
*/
}

static void neighbor_free(Neighbor *neighbor)
{
    free(neighbor->ranges.data);
    free(neighbor);
}

// ping neighbors
void neighbors_periodic()
{
    /*
    * Make sure neighbors are still there:
    * 1. directly after a DATA packet is send to them and no DATA reply was seen
    * 2. after extended periods (check with exponential backoff)
    */
    Neighbor *neighbor;
    Neighbor *neighbor_tmp;
    HASH_ITER(hh, g_neighbors, neighbor, neighbor_tmp) {
        if ((neighbor->time_updated < gstate.time_now)
                && (gstate.time_now - neighbor->time_updated) > HOP_TIMEOUT_MS) {
            // we have send a DATA packet and have not seen a DATA back or PONG back => send PING
            if (neighbor->pinged > 2) {
                log_debug("neighbors_periodic() remove neighbor %s", str_addr(&neighbor->address));
                neighbors_removed(neighbor);
                HASH_DEL(g_neighbors, neighbor);
                neighbor_free(neighbor);
            } else {
                // A response PONG will update the entry in g_neighbors and g_nodes.
                PING ping = {
                    .type = TYPE_PING,
                    .seq_num = packets_next_sequence_number(),
                };
                log_debug("neighbors_periodic() ping neighbor %s", str_addr(&neighbor->address));
                send_ucast_wrapper(&neighbor->address, &ping, sizeof(ping));
                neighbor->pinged += 1;
            }
        }
    }
}

/*
// return node behind an address (only possible if neighbor)
// beware: slow - only for debugging
static Node *find_neighbor_node_by_address(const Address *addr)
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        HASH_ITER(hh, node->hops, hop, htmp) {
            if (hop->hop_count == 1 && 0 == memcmp(&hop->next_hop_addr, addr, sizeof(Address))) {
                return node;
            }
        }
    }

    return NULL;
}
*/

/*
static uint32_t get_neighbor_id(const Neighbor *neighbor)
{
    Node *node = find_neighbor_node_by_address(&neighbor->address);
    return node ? node->id : 0;
}
*/
