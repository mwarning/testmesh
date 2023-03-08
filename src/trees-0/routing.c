#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

#include "../ext/uthash.h"
#include "../log.h"
#include "../utils.h"
#include "../tun.h"
#include "../net.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"

#include "routing.h"

#define TIMEOUT_NEIGHBOR 30
#define ROOT_SEND_INTERVAL 2 // timeout and send root every seconds
#define MAX_PATH_COUNT 32

enum {
    TYPE_DATA,
    TYPE_ROOT
};

typedef struct {
    Address addr;
    time_t last_seen;
    time_t expected_response; // 0 is unknown
    uint32_t path_length;
    uint32_t path[MAX_PATH_COUNT];
    UT_hash_handle hh;
} Neighbor;

typedef struct Root {
    Address parent_addr;
    uint8_t full_flood;
    uint32_t root_id;
    uint16_t seq_num;
    uint16_t updated_count;
    time_t last_updated;
    uint32_t path_length;
    uint32_t path[MAX_PATH_COUNT];
} Root;

// packet to create span the tree
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t full_flood;
    uint32_t root_id;
    uint16_t seq_num;
    uint16_t path_length; // might not be needed
    uint32_t path[MAX_PATH_COUNT];
} ROOT;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num; // sequence number - not needed
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t payload_length;
} DATA;

//static uint16_t g_sequence_number = 0;
static uint8_t g_is_critical = 1; // rename to relay_broadcasts?
static time_t g_is_critical_time = 0; // for timeout
static Neighbor *g_neighbors = NULL;
static Root g_root = {0};

static uint8_t* get_data_payload(DATA *p)
{
    return ((uint8_t*) p) + sizeof(DATA);
}

static size_t get_data_size(DATA *p)
{
    return sizeof(DATA) + p->payload_length;
}

static size_t get_root_size(ROOT *p)
{
    return offsetof(ROOT, path) + p->path_length * sizeof(uint32_t);
}

static uint32_t* get_root_path(ROOT *p)
{
    return (uint32_t*) (((uint8_t*) p) + offsetof(ROOT, path));
}

static void neighbors_timeout()
{
    Neighbor *cur;
    Neighbor *tmp;

    HASH_ITER(hh, g_neighbors, cur, tmp) {
        if ((cur->last_seen + TIMEOUT_NEIGHBOR) < gstate.time_now) {
            log_debug("timeout neighbor %s", str_addr(&cur->addr));
            HASH_DEL(g_neighbors, cur);
            free(cur);
        }
    }
}

static Neighbor *neighbors_lookup(const Address *addr)
{
    Neighbor *cur;

    HASH_FIND(hh, g_neighbors, addr, sizeof(Address), cur);

    return cur;
}

static Neighbor *neighbors_update(const Address *addr, uint32_t path_length, const uint32_t *path)
{
    Neighbor *cur;

    cur = neighbors_lookup(addr);
    if (cur) {
        if (0 == memcmp(addr, &cur->addr, sizeof(Address))) {
            cur->last_seen = gstate.time_now;
            cur->path_length = path_length;
            memcpy(&cur->path[0], path, path_length * sizeof(uint32_t));
        } else {
            // discard by timeout
        }
    } else {
        cur = (Neighbor*) malloc(sizeof(Neighbor));
        cur->addr = *addr;
        cur->last_seen = gstate.time_now;
        cur->expected_response = 0;
        cur->path_length = path_length;
        memcpy(&cur->path[0], path, path_length * sizeof(uint32_t));

        HASH_ADD(hh, g_neighbors, addr, sizeof(Address), cur);
    }

    return cur;
}

static void handle_DATA(const Address *rcv, const Address *src, const Address *dst, DATA *p, size_t length)
{
    // we expect (unicast) packets for us only
    if (!address_equal(rcv, dst)) {
        log_trace("DATA: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length < sizeof(DATA) || length != get_data_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    log_debug("DATA: got packet: %s / 0x%08x => 0x%08x",
        str_addr(src), p->src_id, p->dst_id);

    if (p->src_id == gstate.own_id) {
        log_debug("DATA: own source id => drop packet");
        return;
    }

    //neighbors_update(src, path, p->path_length);

/*
    Entry *entry = entry_find(p->src_id);

    if (entry) {
        entry->last_updated = gstate.time_now;
        if (p->seq_num <= entry->seq_num) {
            // old packet => drop
             log_debug("drop packet with old sequence number %d (current is %d)",
                (int) p->seq_num, (int) entry->seq_num);
            return;
        } else {
            entry->seq_num = p->seq_num;
        }
    } else {
        entry = entry_add(p->src_id, p->seq_num);
    }

    if (p->dst_id == gstate.own_id) {
        log_debug("write %u bytes to %s", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        tun_write(p->payload, p->length);
    } else {
        log_debug("send mcasts");
        send_mcasts(p, recv_len);
    }
*/
}

static const char *str_path(const uint32_t *path, uint32_t path_length)
{
    static char buf[MAX_PATH_COUNT * 25];
    char *cur = buf;
    cur[0] = 0;
    for (size_t i = 0; i < path_length; i++) {
        ssize_t left = (buf + sizeof(buf)) - cur;
        cur += snprintf(cur, left, i ? ", %u" : "%u", path[i]);
    }
    return buf;
}

static int path_contains_own(const ROOT *p)
{
    if (p->root_id == gstate.own_id) {
        return 1;
    }

    for (size_t i = 0; i < p->path_length; i++) {
        if (p->path[i] == gstate.own_id) {
            return 1;
        }
    }
    return 0;
}

static void set_critical(uint8_t is_critical)
{
    log_debug("set critical: %s (was %s)", str_enabled(is_critical), str_enabled(g_is_critical));
    g_is_critical = is_critical;
    g_is_critical_time = gstate.time_now;
}

static void handle_ROOT(const Address *rcv, const Address *src, const Address *dst, ROOT *p, size_t length)
{
    if (length < offsetof(ROOT, path)
            || length != get_root_size(p)
            || p->path_length >= MAX_PATH_COUNT) {
        log_debug("ROOT: invalid packet size => drop");
        return;
    }

    uint32_t path_length = p->path_length;
    uint32_t path[MAX_PATH_COUNT];
    memcpy(path, get_root_path(p), path_length * sizeof(uint32_t));

    uint8_t is_echo = path_contains_own(p);
    // //(path_length >= 2 && path[path_length - 2] == gstate.own_id);

    log_debug("ROOT: got packet from %s, seq_num: %u, full_flood: %s, path: %u:[%s], is_echo: %s",
        str_addr(src), p->seq_num, str_enabled(p->full_flood), p->root_id,
        str_path(path, path_length), str_enabled(is_echo));

    Neighbor *neigh = neighbors_update(src, path_length, path);

    Root *root = &g_root;

    log_debug("root_id: %u %u, seq_num: %u %u, critical: %s",
        p->root_id, root->root_id, p->seq_num, root->seq_num, str_enabled(g_is_critical));

    if (p->root_id == root->root_id) {
        if (p->seq_num <= root->seq_num) {
            if (p->full_flood && is_echo) {
                log_trace("ROOT: old sequence number and full flood echo => critical");
                set_critical(1);
            } else {
                log_trace("ROOT: old sequence number => ignore");
            }
        } else if (path_length > root->path_length) {
            log_trace("ROOT: got longer path => ignore");
        } else {
            /*
            if (root->full_flood) {
                set_critical(0);
            }
            */
            log_debug("ROOT: shorter or equal path => update");
            if (0 == memcmp(&root->parent_addr, src, sizeof(Address))) {
                root->updated_count += 1;
            } else {
                root->parent_addr = *src;
            }
            root->seq_num = p->seq_num;
            root->full_flood = p->full_flood;
            root->last_updated = gstate.time_now;
            root->path_length = path_length;
            memcpy(&root->path[0], &path[0], path_length * sizeof(uint32_t));

            // append own id
            root->path[root->path_length] = gstate.own_id;
            root->path_length += 1;
        }
    } else if (p->root_id < root->root_id) {
        log_debug("ROOT: got smaller root id => take");
        root->parent_addr = *src;
        root->root_id = p->root_id;
        root->updated_count = 0;
        root->seq_num = p->seq_num;
        root->full_flood = p->full_flood;
        root->last_updated = gstate.time_now;
        root->path_length = path_length;
        memcpy(&root->path[0], get_root_path(p), path_length * sizeof(uint32_t));

        // append own id
        root->path[root->path_length] = gstate.own_id;
        root->path_length += 1;
    } else {
        log_trace("ROOT: got bigger root id => ignore");
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    /*
    Neighbor *e = neighbors_lookup(dst_id);
    if (e) {
        // 
    } else {
        log_debug("no next hop for => drop");
    }*/
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    if (!address_is_broadcast(dst) && !address_equal(dst, rcv)) {
        // packet is not for us (possible e.g. when device is in monitor mode)
        return;
    }

    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(rcv, src, dst, (DATA*) packet, packet_length);
        break;
    case TYPE_ROOT:
        handle_ROOT(rcv, src, dst, (ROOT*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s", packet[0], str_addr(src));
    }
}

static void reset_root()
{
    log_debug("reset_root");

    g_root = (Root) {
        .root_id = gstate.own_id,
        .last_updated = gstate.time_now,
        .full_flood = 1,
    };
}

static void send_root()
{
    ROOT root = {
        .type = TYPE_ROOT,
        .full_flood = g_root.full_flood,
        .root_id = g_root.root_id,
        .seq_num = g_root.seq_num,
        .path_length = g_root.path_length,
    };
    memcpy(get_root_path(&root), &g_root.path[0], g_root.path_length * sizeof(uint32_t));

    log_debug("send_root: root_id: %u:[%s], full_flood: %s",
        g_root.root_id,
        str_path(&g_root.path[0], g_root.path_length),
        str_enabled(g_root.full_flood));

    send_bcasts_l2(&root, get_root_size(&root));
}

static void periodic_handler()
{
    neighbors_timeout();

    if (gstate.time_now % ROOT_SEND_INTERVAL == 0) {
        if (g_root.root_id == gstate.own_id) {
            // as critical node, we initiate floods
            if ((g_root.updated_count % 16) == 0) {
                g_root.full_flood = 1;
            } else {
                g_root.full_flood = 0;
            }

            // we are the root
            send_root();

            log_debug("I am root");
            set_critical(1);

            // pretend we received our own announcement (needed?)
            g_root.updated_count += 1;
            g_root.last_updated = gstate.time_now;

            // change sequence number (only for our own root!)
            g_root.seq_num += 1;
        } else if (g_is_critical || g_root.full_flood == 1) {
            // forward flood if we are critical or this is a full_flood

            // make sure we are critical after 30 seconds of no update
            if ((g_is_critical_time + 32) < gstate.time_now) {
                log_debug("timeout for critical");
                set_critical(0);
            }

            // reset root if we have not heard from the current root for some time 
            if ((g_root.last_updated + 30) < gstate.time_now) {
                log_debug("timeout for root");
                reset_root();
            }

            // forward other root
            send_root();
        }
    }
}

static int console_handler(FILE* fp, int argc, char* argv[])
{
    #define MATCH(n, cmd) ((n) == argc && !strcmp(argv[0], (cmd)))

    if (MATCH(1, "h")) {
        fprintf(fp, "r:                       print current root\n");
        fprintf(fp, "n:                       print neighbor table\n");
    } else if (MATCH(1, "r")) {
        Root *root = &g_root;
        fprintf(fp, "path:     %u:[%s]\n", root->root_id, str_path(&root->path[0], root->path_length));
        fprintf(fp, "addr:     %s\n", str_addr(&root->parent_addr));
        fprintf(fp, "updated:  %s\n", str_ago(root->last_updated));
        fprintf(fp, "count:    %u\n", root->updated_count);
        fprintf(fp, "critical: %s (%s ago)\n", str_enabled(g_is_critical), str_ago(g_is_critical_time));
    } else if (MATCH(1, "n")) {
        Neighbor *cur;
        Neighbor *tmp;

        fprintf(fp, "id seq_num last_seen\n");
        HASH_ITER(hh, g_neighbors, cur, tmp) {
            fprintf(fp, "  %s %s %s\n",
                str_addr(&cur->addr),
                str_ago(cur->last_seen),
                (cur->expected_response == 0) ?
                    "unknown" : str_duration(gstate.time_now, cur->expected_response)
            );
        }
    } else {
        return 1;
    }

    return 0;
}

static void init()
{
    uint32_t tms = (uint32_t) rand();
    usleep(tms % 1000);

    set_critical(0);
    reset_root();

    // call at least every second
    net_add_handler(-1, &periodic_handler);
}

void trees_0_register()
{
    static const Protocol p = {
        .name = "trees-0",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console = &console_handler,
    };

    protocols_register(&p);
}
