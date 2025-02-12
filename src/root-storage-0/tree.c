#include <assert.h>

#include "../log.h"
#include "../main.h"

#include "tree.h"
#include "ifstates.h"
#include "ranges.h"
#include "neighbors.h"


// for when we are root
static Root g_root = {0};

// for debugging
static Neighbor *g_parent = NULL;

// TODO: call when we become root
void tree_init()
{
    memset(&g_root, 0, sizeof(Root));
    g_root.tree_id = gstate.own_id; // TODO: rand(), reinitialize when we become root
}

Root *tree_get_root()
{
    return &g_root;
}

void tree_neighbor_removed(const Neighbor *neighbor)
{
    if (neighbor == g_parent) {
        g_parent = NULL;
    }
}

Neighbor *tree_get_parent()
{
    Neighbor *parent = NULL;
    Neighbor *neighbor;
    Neighbor *neighbor_tmp;

    //uint64_t timeout_ms = 8200; //1200;

    int reason = -1; // reason why we switched parent

    HASH_ITER(hh, neighbors_all(), neighbor, neighbor_tmp) {
        if (!neighbor->root_set) {
            // Ignore neighbors that have not send us a ROOT_CREATE packet yet.
            continue;
        }

        //log_debug("get_parent() iter: %s tree_id: 0x%08x, root_seq_num: %d",
        //    str_addr(&neighbor->address), neighbor->root.tree_id, (int) neighbor->root.root_seq_num);

        if (parent == NULL) {
            // No parent yet, set first one.
            // TODO: should we set us as root?
            parent = neighbor;
            reason = 1;
            continue;
        }

        // TODO: use dynamic timeout
        //neighbor->root.root_recv_time
        uint64_t timeout_ms = neighbor->root.root_next_send_ms * 2 + (neighbor->root.root_next_send_ms / 16);
        bool is_neighbor_overdue = (neighbor->root.root_recv_time + timeout_ms) < gstate.time_now;
        bool is_cur_overdue = (parent->root.root_recv_time + timeout_ms) < gstate.time_now;

//log_debug("parent: is_overdue: %s, neighbor: is_overdue: %s", str_bool(is_cur_overdue), str_bool(is_neighbor_overdue));

        if (is_neighbor_overdue != is_cur_overdue) {
            if (is_cur_overdue) {
                // parent is overdue, but neighbor is not
                parent = neighbor;
                reason = 2;
            } else {
                // neighbor is overdue, but parent is not => ignore
                continue;
            }
        } else {
            // both are overdue or not
            if (neighbor->root.tree_id > parent->root.tree_id) {
                parent = neighbor;
                reason = 3;
            } else if (neighbor->root.tree_id == parent->root.tree_id) {
                uint16_t neighbor_scope = address_scope(&neighbor->address);
                uint16_t cur_scope = address_scope(&parent->address);

                if (neighbor_scope != cur_scope) {
                    if (neighbor_scope > cur_scope) {
                        log_debug("choose by address scope");
                        parent = neighbor;
                        reason = 4;
                    } else {
                        continue;
                    }
                }

                if (neighbor->root.hop_count < parent->root.hop_count) {
                    parent = neighbor;
                    reason = 5;
                } else if (neighbor->root.hop_count == parent->root.hop_count) {
                    int cmp = memcmp(&neighbor->address, &parent->address, sizeof(Address));
                    if (cmp > 0) {
                        parent = neighbor;
                        reason = 6;
                    }
                } else {
                    continue;
                }
            }
        }
    }

    if (parent) {
        // see if we are root (return NULL)
        if (parent->root_set) {
            uint64_t timeout_ms = parent->root.root_next_send_ms * 2 + (parent->root.root_next_send_ms / 16);
            bool is_cur_overdue = (parent->root.root_recv_time + timeout_ms) < gstate.time_now;
            if (is_cur_overdue) {
                // we are root
                parent = NULL;
                reason = 7;
            } else {
                if (g_root.tree_id > parent->root.tree_id) {
                    //log_debug("get_parent() => 0x%08x > 0x%08x we are root", g_root.tree_id, parent->root.tree_id);
                    // we are root
                    parent = NULL;
                    reason = 8;
                }
            }
        } else {
            // we are root
            parent = NULL;
            reason = 9;
        }
    }

    // for debugging
    if (g_parent != parent) {
        if (g_parent && parent) {
            log_debug("get_parent(): parent changed (0x%08x -> 0x%08x, reason: %d, %s %s)",
                g_parent->root.tree_id, parent->root.tree_id, reason,
                str_since(g_parent->root.root_recv_time), str_since(parent->root.root_recv_time));
        } else if (parent) {
            log_debug("get_parent(): parent changed (none -> 0x%08x), reason: %d", parent->root.tree_id, reason);
        } else if (g_parent) {
            log_debug("get_parent(): parent changed (0x%08x -> none), reason: %d", g_parent->root.tree_id, reason);
        } else {
            log_debug("get_parent(): parent changed (none -> none), reason: %d", reason);
        }
        g_parent = parent;
    }

    return parent;
}

// used for ROOT_CREATE and PING packets only
// Do we want to use PING as well, or better send ROOT_CREATE?
static void send_bcast_wrapper(const char *context, /*const IFState *interface,*/ ROOT_CREATE *packet)
{
    uint8_t bandwidth_incoming = packet->bandwidth; // from parent interface
    size_t packet_size = sizeof(ROOT_CREATE);

    //if (interface == NULL) {
        // default route (Internet)
        Neighbor *neighbor;
        Neighbor *neighbor_tmp;
        HASH_ITER(hh, neighbors_all(), neighbor, neighbor_tmp) {
            int af = neighbor->address.family;
            if (af == AF_INET || af == AF_INET6) {
                //if (is_lan_address(&neighbor->address)) {
                    packet->bandwidth = bandwidth_incoming;
                    send_ucast_l3(&neighbor->address, packet, packet_size);
                //} else {
                    //send_bcast_l3(&neighbor->address, packet, packet_size);
                //}
            }
        }
    //}

    IFState *ifstate;
    IFState *ifstate_tmp;
    HASH_ITER(hh, ifstates_all(), ifstate, ifstate_tmp) {
        enum INTERFACE_TYPE interface_type = get_interface_type(ifstate->ifindex);
        uint8_t bandwidth_outgoing = interface_type;
        packet->bandwidth = MIN(bandwidth_incoming, bandwidth_outgoing);

        //packet->bandwidth = MIN(ifstate->ifindex);
        if (ENABLE_OPTIMIZED_BROADCAST
                && interface_type == INTERFACE_TYPE_WLAN
                && ifstate->neighbor_count <= 4) {
            // send a broadcast as multiple unicast packets instead of a broadcast
            // TODO: when is not a good idea even when there few neighbors?
            //     - when we really need to broadcast to reach unknown neihgbors (or does everybody run in promiscious mode?) 
            
            Neighbor *neighbor;
            Neighbor *neighbor_tmp;
            HASH_ITER(hh, neighbors_all(), neighbor, neighbor_tmp) {
                if (ifstate->ifindex == address_ifindex(&neighbor->address)) {
                    send_ucast_l2(&neighbor->address, packet, packet_size);
                    record_traffic(&ifstate->unicast_traffic, packet_size, 0);
                }
            }
        } else {
            ifstate->send_broadcast_time = gstate.time_now;

            send_bcast_l2(ifstate->ifindex, packet, packet_size);
            record_traffic(&ifstate->broadcast_traffic, packet_size, 0);
        }
    }
}

// called every time we need to consider sending a ROOT_CREATE packet
static bool send_ROOT_CREATE()
{
    /*
    // got own packet
    ifstate->recv_own_broadcast_time = gstate.time_now;
    memcpy(&ifstate->recv_own_broadcast_address, src, sizeof(Address));

    // root has changed
    neighbor->root.time_created = gstate.time_now;

    // record root
    neighbor->root_set = true;
    neighbor->root.tree_id = p->tree_id;
    neighbor->root.hop_count = p->hop_count;
    neighbor->root.root_seq_num = p->root_seq_num;
    neighbor->root.root_recv_time = gstate.time_now;
    neighbor->root.root_next_send_ms = p->next_send_ms; // todo, consider in timeout in tree_get_parent()
    neighbor->root.parent_id = p->sender; // for debugging?

    // parent changed
    new_parent->root.store_send_counter = 0;
    new_parent->root.store_send_time = 0;
    ifstate->neighborhood_changed_time = gstate.time_now;
    */
    /*
    ongoing taks: decouple receival of ROOT_CREATE and send interval
    TODO: check if it is time to send a new packet

aim:
 - send packet right after we got a root packet we want to forward
 - if there a too much, we send less, half the pace
 (- if there not enough, send double the rate; is that even a good idea?)
 - if a parent changes, try to send the next

    */
    Neighbor* parent = tree_get_parent();
    if (parent && parent->root_set) {
        IFState *ifstate = ifstates_get(&parent->address);
        const Root* root = &parent->root;

        // we are not root
        ROOT_CREATE p = {
            .type = TYPE_ROOT_CREATE,
            .tree_id = root->tree_id,
            .root_seq_num = root->root_seq_num,
            .next_send_ms = root->root_next_send_ms,
            .bandwidth = root->bandwidth,
            .hop_count = MIN(root->hop_count + 1U, UINT8_MAX),
            .sender = gstate.own_id,
            .prev_sender = root->parent_id,
        };

        bool is_needed = (ifstate->send_broadcast_time == 0)
            || ((ifstate->recv_own_broadcast_time + 10000) > gstate.time_now); // g_send_broadcast_time);

        log_debug("send_ROOT_CREATE: is_needed: %s, next_send_ms: %d", str_bool(is_needed), (int) p.next_send_ms);
        if (is_needed) {
            ifstate->send_broadcast_time = gstate.time_now;
            send_bcast_wrapper("send_ROOT_CREATE", &p);
            return true;
        } else {
            return false;
        }
    } else if (parent == NULL) {
        // we are root!
#define ROOT_CREATE_MIN_SEND_INTERVAL_MS 1000
#define ROOT_CREATE_MAX_SEND_INTERVAL_MS 10000

        IFState *ifstate;
        IFState *tmp;
        HASH_ITER(hh, ifstates_all(), ifstate, tmp) {
            uint32_t send_interval_ms = ifstate->ROOT_CREATE_send_interval_ms;
            if (g_root.root_send_time == 0 || (g_root.root_send_time + send_interval_ms) <= gstate.time_now) {
                g_root.root_send_time = gstate.time_now;

                if (ENABLE_OPTIMIZED_ROOT_CREATE) {
                    // should maintain an interval per interface?
                    bool neighborhood_changed = (ifstate->neighborhood_changed_time > ifstate->send_broadcast_time);
                    if (neighborhood_changed) {
                        // reset interval
                        send_interval_ms = ROOT_CREATE_MIN_SEND_INTERVAL_MS;
                    } else if (send_interval_ms < ROOT_CREATE_MAX_SEND_INTERVAL_MS) {
                        send_interval_ms *= 2;
                    }
                } else {
                    send_interval_ms = ROOT_CREATE_MIN_SEND_INTERVAL_MS;
                }

                ROOT_CREATE p = {
                    .type = TYPE_ROOT_CREATE,
                    .tree_id = gstate.own_id,
                    .root_seq_num = g_root.root_seq_num++,
                    .next_send_ms = send_interval_ms,
                    .hop_count = 1,
                    .sender = gstate.own_id,
                    .prev_sender = gstate.own_id
                };

                log_debug("send_ROOT_CREATE send ROOT_CREATE (tree_id: 0x%08x, seq_num: %d, hop_count: %u)",
                    p.tree_id, p.root_seq_num, p.hop_count);

                send_bcast_wrapper("send_ROOT_CREATE_periodic", &p);

                ifstate->ROOT_CREATE_send_interval_ms = send_interval_ms;
            }
        }
        return true;
    }

    return false;
}

bool neighbor_is_child(const Neighbor *neighbor)
{
    if (neighbor->root_store_received_time > 0) {
        return neighbor->is_child;
    } else {
        // is_child has not been set via a ROOT_CREATE packet
        return false;
    }

#if 0
    const uint64_t us = neighbor->root_store_to_us_received_time;
    const uint64_t others = neighbor->root_store_to_others_received_time;
//    const uint64_t now = gstate.time_now;

    if (us == 0) {
        return false;
    }

    if (us < others) {
        return false;
    }
/*
    // needed?
    if (us <= now && ((now - us) > HOP_TIMEOUT_MS)) {
        // child timed out
        return false;
    }
*/
    return true;
#endif
}

static void collect_ranges_from_children(Ranges *ranges)
{
    // add own id
    ranges_add(ranges, gstate.own_id, 0);

    int i = 0;
    Neighbor *neighbor;
    Neighbor *tmp;
    HASH_ITER(hh, neighbors_all(), neighbor, tmp) {
        // only include children
        if (neighbor_is_child(neighbor)) {
            //log_debug("send_ROOT_STORE_periodic: [%d] neighbor ranges: %s", i, ranges_str(&neighbor->ranges));
            ranges_add_all(ranges, &neighbor->ranges);
            i += 1;
        }
    }
}

// small helper - timeout duration is over
static bool over(uint64_t time, uint64_t duration)
{
    return time == 0 || (time + duration) <= gstate.time_now;
}

static void send_ROOT_STORE_periodic()
{
#define ROOT_STORE_MIN_SEND_INTERVAL_MS 1000
#define ROOT_STORE_MAX_SEND_INTERVAL_MS 10000

    static Ranges prev_ranges = {0};
    static Ranges ranges = {0};
    static uint64_t interval_ms = ROOT_STORE_MIN_SEND_INTERVAL_MS;
    static Address parent_address = {0};

    Neighbor *parent = tree_get_parent();

    if (parent) {
        ranges_clear(&ranges);
        collect_ranges_from_children(&ranges);
        ranges_merge(&ranges, 1);

        bool ranges_changed = false;
        bool parent_changed = false;

        if (ENABLE_OPTIMIZED_ROOT_STORE) {
            if (!address_equal(&parent_address, &parent->address)) {
                // parent changed
                parent_changed = true;
                parent_address = parent->address;
            }

            ranges_changed = !ranges_same(&ranges, &prev_ranges);
        } else {
            // send every second in any case
            interval_ms = ROOT_STORE_MIN_SEND_INTERVAL_MS;
        }

        bool send_now = over(parent->root.store_send_time, interval_ms);

        // send ranges to parent
        if (parent_changed || ranges_changed || send_now) {
            ROOT_STORE p = {
                .type = TYPE_ROOT_STORE,
            };

            // bytes available for ranges
            size_t data_size_max = FIELD_SIZEOF(ROOT_STORE, data);
            int ranges_bytes = ranges_compress(&p.data[0], data_size_max, &ranges);

            if (ranges_bytes != -1) {
                assert(ranges_bytes > 0 && ranges_bytes <= data_size_max);
                log_debug("send_ROOT_STORE_periodic: send to %s, ranges_bytes: %d, spans: %d, ranges: %s, interval_ms: %s",
                    str_addr(&parent->address), (int) ranges_bytes, (int) ranges_span(&ranges),
                    ranges_str(&ranges), str_time(interval_ms));
                bool was_send = send_ucast_wrapper(&parent->address, &p, offsetof(ROOT_STORE, data) + ranges_bytes);

                if (was_send) {
                    parent->root.store_send_counter += 1;
                    parent->root.store_send_time = gstate.time_now;

                    ranges_swap(&ranges, &prev_ranges);

                    if (send_now) {
                        // double interval
                        interval_ms = MIN(interval_ms * 2, ROOT_STORE_MAX_SEND_INTERVAL_MS);
                    } else {
                        // reset interval
                        interval_ms = ROOT_STORE_MIN_SEND_INTERVAL_MS;
                    }
                }
            } else {
                log_error("failed to compress ranges");
                // assume to be send, we do not want to fail over and over again 
            }
        }
    }
}

void handle_ROOT_STORE(IFState *ifstate, Neighbor *neighbor, const Address *src, uint8_t flags, ROOT_STORE *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast) {
        log_trace("ROOT_STORE: broadcast destination => ignore");
        return;
    }

    ranges_clear(&neighbor->ranges);

    int data_size = length - offsetof(ROOT_STORE, data);
/*
    char buf[200];
    hex_dump(buf, sizeof(buf), &p->data[0], data_size);
    log_debug(buf);
*/
    int rc = ranges_decompress(&neighbor->ranges, &p->data[0], data_size);
    if (rc == -1) {
        neighbor->ranges_set = false;
        log_warning("ROOT_STORE: failed to decompress ranges from %s", str_addr(src));
    } else {
        neighbor->ranges_set = true;
        neighbor->root_store_received_time = gstate.time_now;
        neighbor->is_child = is_destination;

        log_debug("ROOT_STORE: got packet from %s, is_destination: %s, bytes: %d, span: %d, ranges: %s",
            str_addr(src), str_bool(neighbor->is_child), data_size, (int) ranges_span(&neighbor->ranges),
            ranges_str(&neighbor->ranges));
    }
}

void handle_ROOT_CREATE(IFState *ifstate, Neighbor *neighbor, const Address *src, uint8_t flags, ROOT_CREATE *p, size_t length)
{
    bool is_destination = flags & FLAG_IS_DESTINATION;

    // might be broadcast or unicast packet (e.g. per Internet)
    if (!is_destination) {
        log_trace("handle_ROOT_CREATE: not for us => drop");
        return;
    }

    if (length != sizeof(ROOT_CREATE)) {
        log_trace("handle_ROOT_CREATE: invalid packet size => drop");
        return;
    }

    if (p->hop_count == 0 || p->hop_count == 255) {
        log_trace("handle_ROOT_CREATE: invalid hop count => drop");
        return;
    }

    if (p->tree_id == gstate.own_id) {
        // there is no point in forwarding it
        log_trace("handle_ROOT_CREATE: packet that says that we are root => drop");
        return;
    }

    const uint64_t now = gstate.time_now;

    // might be prefix or hash?
    if (p->prev_sender == gstate.own_id) {
        // We are the previous sender => that neighbor relies on our broadcasts.
        // Packet will be dropped further down based on seq_num.
        log_debug("handle_ROOT_CREATE: got own packet");
        ifstate->recv_own_broadcast_time = now;
        memcpy(&ifstate->recv_own_broadcast_address, src, sizeof(Address));
    }

    // current (potentially) parent or null if we are root
    Neighbor *cur_parent = tree_get_parent();

    // drop packet if we already got this or an older packet from the current parent
    if (cur_parent && cur_parent->root_set && cur_parent->root.tree_id == p->tree_id
            && !is_newer_seqnum(cur_parent->root.root_seq_num, p->root_seq_num)) {
        return;
    }

    // drop packet if we already got this or an older packet from this neighbor
    if (neighbor && neighbor->root_set && neighbor->root.tree_id == p->tree_id
            && !is_newer_seqnum(neighbor->root.root_seq_num, p->root_seq_num)) {
        // duplicate packet
        log_debug("handle_ROOT_CREATE: duplicate packet from %s tree_id: 0x%08x, seq_num: %d",
            str_addr(&neighbor->address), p->tree_id, p->root_seq_num);
        return;
    }

    if (!neighbor->root_set || neighbor->root.tree_id != p->tree_id) {
        // record last time the root changed
        neighbor->root.time_created = now;
    }

    neighbor->root_set = true;
    neighbor->root.tree_id = p->tree_id;
    neighbor->root.hop_count = p->hop_count;
    neighbor->root.root_seq_num = p->root_seq_num;
    neighbor->root.root_recv_time = now;
    neighbor->root.root_next_send_ms = p->next_send_ms; // todo, consider in timeout in tree_get_parent()
    neighbor->root.parent_id = p->sender; // for debugging?

    Neighbor* new_parent = tree_get_parent();

    if (cur_parent != new_parent) {
        log_debug("handle_ROOT_CREATE: parent changed");

        new_parent->root.store_send_counter = 0;
        new_parent->root.store_send_time = 0;
        ifstate->neighborhood_changed_time = now;
    }

    // only forward root packet from parent
    if (new_parent && new_parent == neighbor) {
        log_debug("handle_ROOT_CREATE: got packet from %s tree_id: 0x%08x, root_seq_num: %d => forward",
            str_addr(&neighbor->address), p->tree_id, (int) p->root_seq_num);

        bool is_send = send_ROOT_CREATE();
        if (is_send) {
            neighbor->root.root_send_time = now;
        }
    } else {
        log_trace("handle_ROOT_CREATE: got packet from %s tree_id: 0x%08x, root_seq_num: %d => drop",
            str_addr(&neighbor->address), p->tree_id, (int) p->root_seq_num);
    }
}

void tree_periodic()
{
    send_ROOT_CREATE();
    send_ROOT_STORE_periodic();
}

/*
static void send_ROOT_CREATE_periodic()
{
#define ROOT_CREATE_MIN_SEND_INTERVAL_MS 1000
#define ROOT_CREATE_MAX_SEND_INTERVAL_MS 10000

    if (we_are_root()) {
        IFState *ifstate;
        IFState *tmp;
        HASH_ITER(hh, ifstates_all(), ifstate, tmp) {
            uint32_t send_interval_ms = ifstate->ROOT_CREATE_send_interval_ms;
            if (g_root.root_send_time == 0 || (g_root.root_send_time + send_interval_ms) <= gstate.time_now) {
                g_root.root_send_time = gstate.time_now;

                if (ENABLE_OPTIMIZED_ROOT_CREATE) {
                    // should maintain an interval per interface?
                    bool neighborhood_changed = (ifstate->neighborhood_changed_time > ifstate->send_broadcast_time);
                    if (neighborhood_changed) {
                        // reset interval
                        send_interval_ms = ROOT_CREATE_MIN_SEND_INTERVAL_MS;
                    } else if (send_interval_ms < ROOT_CREATE_MAX_SEND_INTERVAL_MS) {
                        send_interval_ms *= 2;
                    }
                } else {
                    send_interval_ms = ROOT_CREATE_MIN_SEND_INTERVAL_MS;
                }

                ROOT_CREATE p = {
                    .type = TYPE_ROOT_CREATE,
                    .tree_id = gstate.own_id,
                    .root_seq_num = g_root.root_seq_num++,
                    .next_send_ms = send_interval_ms,
                    //.required_send = ((send_counter++ % 4) == 0), // set true for every 4th packet
                    .hop_count = 1,
                    .sender = gstate.own_id,
                    .prev_sender = gstate.own_id
                };

                log_debug("send_ROOT_CREATE_periodic send ROOT_CREATE (tree_id: 0x%08x, seq_num: %d, hop_count: %u)",
                    p.tree_id, p.root_seq_num, p.hop_count);

                send_bcast_wrapper("send_ROOT_CREATE_periodic", &p, sizeof(ROOT_CREATE));

                ifstate->ROOT_CREATE_send_interval_ms = send_interval_ms;
            }
        }
    }
}*/
