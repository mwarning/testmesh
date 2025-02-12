#include "../main.h"
#include "../log.h"

#include "packets.h"
#include "nodes.h"


static Node *g_nodes = NULL;

Node *nodes_all()
{
	return g_nodes;
}

Node *next_node_by_id(uint32_t id)
{
    Node *node;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

    return node;
}

static void nodes_added(const Node *node)
{
}

static void node_removed(const Node *node)
{
}

void nodes_remove(Node *node)
{
	HASH_DEL(g_nodes, node);
	node_removed(node);
	free(node);
}

// add uint16_t age bias
bool nodes_update(uint32_t id, const Address *addr, uint16_t hop_count, uint32_t seq_num, uint16_t age_bias)
{
    bool is_new_packet = packets_is_duplicate(id, seq_num);

    if (id != gstate.own_id) {
        //log_debug("nodes_update() id: 0x%08x, addr: %s, hop_count: %d, seq_num: %d, age_bias: %d",
        //    id, str_addr(addr), (int) hop_count, (int) seq_num, (int) age_bias);
        Node *node;
        Hop *hop;

        HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);
        if (node == NULL) {
            // add new entry
            node = (Node*) malloc(sizeof(Node));
            node->time_created = gstate.time_now;
            node->id = id;
            if (seq_num != UNKNOWN_SEQUENCE_NUMBER) {
                node->seq_num = seq_num;
            } else {
                node->seq_num = 0;
            }
            node->hops = NULL;
            HASH_ADD(hh, g_nodes, id, sizeof(uint32_t), node);
            nodes_added(node);
        }

        HASH_FIND(hh, node->hops, addr, sizeof(Address), hop);
        if (hop == NULL) {
            // add new entry
            hop = (Hop*) malloc(sizeof(Hop));
            hop->time_created = gstate.time_now - age_bias;
            hop->next_hop_addr = *addr;
            HASH_ADD(hh, node->hops, next_hop_addr, sizeof(Address), hop);
        }

        //node->time_seen = gstate.time_now;

        hop->hop_count = hop_count;
        hop->time_updated = gstate.time_now;

        node->time_updated = gstate.time_now;
    }

    return is_new_packet;
}

void nodes_remove_next_hop_addr(const Address *addr)
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;

    Node *g_nodes = nodes_all();
    HASH_ITER(hh, g_nodes, node, ntmp) {
        HASH_ITER(hh, node->hops, hop, htmp) {
            if (0 == memcmp(&hop->next_hop_addr, addr, sizeof(Address))) {
                log_debug("neighbors_remove() remove hop to 0x%08x via %s", node->id, str_addr(&hop->next_hop_addr));
                HASH_DEL(node->hops, hop);
                free(hop);
            }
        }

        if (node->hops == NULL) {
            log_debug("neighbors_remove() remove node 0x%08x", node->id);
            nodes_remove(node);
        }
    }
}

// timeout nodes
void nodes_periodic()
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        HASH_ITER(hh, node->hops, hop, htmp) {
            if ((gstate.time_now - hop->time_updated) > HOP_TIMEOUT_MS) {
                HASH_DEL(node->hops, hop);
                free(hop);
            }
        }

        if (node->hops == NULL) {
            HASH_DEL(g_nodes, node);
            node_removed(node);
            free(node);
        }
    }
}

/*
// not used atm.
// decide if it useful to send a broadcast
static bool is_broadcast_needed_l2(const IFState *ifstate)
{
    bool neighborhood_changed = (ifstate->neighborhood_changed_time > ifstate->send_broadcast_time);
    bool neighborhood_needed = ifstate->recv_own_broadcast_time > 0
            && (ifstate->recv_own_broadcast_time > ifstate->send_broadcast_time);

    log_debug("is_broadcast_needed_l2: recv_own_broadcast_time: %s, send_broadcast_time: %s, neighborhood_changed: %s, neighborhood_needed: %s",
        str_since(ifstate->recv_own_broadcast_time), str_since(ifstate->send_broadcast_time),
        str_bool(neighborhood_changed), str_bool(neighborhood_needed)
    );

    if (ENABLE_OPTIMIZED_ROOT_CREATE) {
        if (neighborhood_needed || neighborhood_changed) {
            log_debug("is_broadcast_needed_l2: neighborhood_changed: %s, neighborhood_needed: %s => true",
                str_bool(neighborhood_changed), str_bool(neighborhood_needed));
            return true;
        } else {
            log_debug("is_broadcast_needed_l2: neighborhood_changed: %s, neighborhood_needed: %s => false",
                str_bool(neighborhood_changed), str_bool(neighborhood_needed));
            return false;
        }
    } else {
        //log_debug("is_broadcast_needed_l2: => true");
        return true;
    }
}*/
