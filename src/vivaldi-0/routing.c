#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <math.h>

#include "../ext/uthash.h"
#include "../log.h"
#include "../utils.h"
#include "../tun.h"
#include "../net.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"

// dimensions
#define DIM 4
#define TIMEOUT_NEIGHBOR_SEC 5
#define COMM_SEND_INTERVAL_SEC 1

enum {
    TYPE_DATA,
    TYPE_COMM,
};

typedef struct {
    uint32_t sender_id;
    Address addr;
    float pos[DIM];
    time_t last_updated;
    UT_hash_handle hh;
} Neighbor;

// only travels one hop to the neighbors
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t sender_id;
    float pos[DIM];
} COMM;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t sender_id;
    uint8_t hop_count;
    float dst_pos[DIM];
    uint16_t length; // might not be needed
    uint8_t payload[2000];
} DATA;


static float g_own_pos[DIM];

static Neighbor *g_neighbors = NULL;

static void vec_mul(float *ret, float b, const float *a)
{
	for (int i = 0; i < DIM; ++i) {
		ret[i] = a[i] * b;
	}
}

static void vec_sub(float *ret, const float *a, const float *b)
{
	for (int i = 0; i < DIM; ++i) {
		ret[i] = a[i] - b[i];
	}
}

static void vec_add(float *ret, const float *a, const float *b)
{
	for (int i = 0; i < DIM; ++i) {
		ret[i] = a[i] + b[i];
	}
}

static void vec_copy(float *ret, const float *a)
{
	for (int i = 0; i < DIM; ++i) {
		ret[i] = a[i];
	}
}

static float vec_len(const float *a)
{
	float sum = 0;
	for (int i = 0; i < DIM; ++i) {
		sum += a[i] * a[i];
	}

	return sqrt(sum);
}

static float vec_dist(const float *a, const float *b)
{
    float d[DIM];
    vec_sub(&d[0], a, b);
    return vec_len(&d[0]);
}

static int is_near_null(const float *v, float eta)
{
	for (int i = 0; i < DIM; ++i) {
		if (v[i] >= eta && v[i] <= -eta) {
			return 0;
		}
	}

	return 1;
}

static void vec_unit(float *unit, const float *a, const float *b)
{
    float dir[DIM];
    vec_sub(&dir[0], a, b);
    float len = vec_len(dir);
    vec_mul(unit, 1.0f / len, dir);
}

static void vec_random_unit(float *ret)
{
	for (int i = 0; i < DIM; ++i) {
		ret[i] = (float) (double) rand();
	}

	float len = vec_len(ret);

	for (int i = 0; i < DIM; ++i) {
		ret[i] /= len;
	}
}

static void neighbor_timeout()
{
    Neighbor *tmp;
    Neighbor *cur;

    HASH_ITER(hh, g_neighbors, cur, tmp) {
        if ((cur->last_updated + TIMEOUT_NEIGHBOR_SEC) < gstate.time_now) {
            log_debug("timeout neighbor 0x%08x", cur->sender_id);
            HASH_DEL(g_neighbors, cur);
        }
    }
}

static Neighbor *neighbor_find(uint32_t sender_id)
{
    Neighbor *cur;
    HASH_FIND(hh, g_neighbors, &sender_id, sizeof(uint32_t), cur);
    return cur;
}

static Neighbor *neighbor_add(uint32_t sender_id, float *pos, const Address *addr)
{
    Neighbor *e = (Neighbor*) malloc(sizeof(Neighbor));

    e->sender_id = sender_id;
    memcpy(&e->pos, pos, sizeof(e->pos));
    memcpy(&e->addr, addr, sizeof(Address));
    e->last_updated = gstate.time_now;

    HASH_ADD_INT(g_neighbors, sender_id, e);

    return e;
}

static void vivaldi_update_simple(float *local_pos, const float *remote_pos, float expected_error)
{
    const float eta = 0.001;
    const float delta = 0.25;
    const float error = expected_error - vec_dist(local_pos, remote_pos);

    // create unit vector in the direction of the error
    float direction[DIM];
    vec_unit(direction, remote_pos, local_pos);

    // use random direction
    if (is_near_null(direction, eta)) {
        vec_random_unit(direction);
    }

    float force[DIM];
    vec_mul(force, error, direction);

    // move a small step in the direction of the force
    for (int i = 0; i < DIM; i++) {
        local_pos[i] += delta * force[i];
    }
}

static void handle_COMM(const Address *from_addr, COMM *p, unsigned recv_len)
{
    if (recv_len != sizeof(COMM)) {
        log_debug("COMM: invalid packet size => drop");
        return;
    }

    log_debug("COMM: got packet: %s / 0x%08x", str_addr(from_addr), p->sender_id);

    if (p->sender_id == gstate.own_id) {
        log_debug("COMM: recevied own packet => drop");
        return;
    }

    float new[DIM];
    float old[DIM];

    Neighbor *neighbor = neighbor_find(p->sender_id);
    if (neighbor) {
        memcpy(&new[0], &p->pos[0], sizeof(new));
        memcpy(&old[0], &neighbor->pos[0], sizeof(old));

        memcpy(&neighbor->pos[0], &new[0], sizeof(neighbor->pos));
        neighbor->last_updated = gstate.time_now;
    } else {
        memcpy(&new[0], &p->pos[0], sizeof(new));
        memcpy(&old[0], &p->pos[0], sizeof(old));

        neighbor = neighbor_add(p->sender_id, &new[0], from_addr);
    }

    vivaldi_update_simple(&g_own_pos[0], &neighbor->pos[0], 1.5f);
}

static void forward_DATA(const DATA *p, unsigned recv_len)
{
    unsigned send_counter = 0;

    float dst_pos[DIM];
    memcpy(&dst_pos[0], &p->dst_pos[0], sizeof(p->dst_pos));

    const float dist_own = vec_dist(&g_own_pos[0], &dst_pos[0]);

    log_debug("dist_own: %.2f", dist_own);

    Neighbor *tmp;
    Neighbor *cur;
    HASH_ITER(hh, g_neighbors, cur, tmp) {
        // propability to transmit from neighbor to destination
        const float dist_neighbor = vec_dist(&cur->pos[0], &dst_pos[0]);
        log_debug("dist_neighbor: %.2f", dist_neighbor);
        if (dist_neighbor > dist_own) {
            send_ucast_l2(&cur->addr, p, recv_len);
            send_counter += 1;
        }
    }

    log_debug("forward data packet to %u neighbors", send_counter);
}

static void handle_DATA(const Address *addr, DATA *p, unsigned recv_len)
{
    if (recv_len < offsetof(DATA, payload) || recv_len != (offsetof(DATA, payload) + p->length)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (p->sender_id == gstate.own_id) {
        log_debug("DATA: own packet => drop");
        return;
    }

    if (p->hop_count > 200) {
        log_warning("max hop count reached (200)");
        return;
    }

    p->sender_id = gstate.own_id;
    p->hop_count += 1;

    forward_DATA(p, recv_len);
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    // TODO:
    //forward_DATA();
}

static void ext_handler_l2(const Address *src_addr, uint8_t *packet, size_t packet_length)
{
    switch (packet[0]) {
    case TYPE_COMM:
        handle_COMM(src_addr, (COMM*) packet, packet_length);
        break;
    case TYPE_DATA:
        handle_DATA(src_addr, (DATA*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s (%s)", packet[0], str_addr(src_addr));
    }
}

static void send_COMMs()
{
    static time_t g_last_send = 0;

    if (g_last_send != 0 && (g_last_send + COMM_SEND_INTERVAL_SEC) > gstate.time_now) {
        return;
    } else {
        g_last_send = gstate.time_now;
    }

    COMM data = {
        .type = TYPE_COMM,
        .sender_id = gstate.own_id,
    };

    memcpy(&data.pos[0], &g_own_pos[0], sizeof(data.pos));

    send_bcasts_l2(&data, sizeof(data));
}

static void periodic_handler(int _events, int _fd)
{
    static time_t g_every_second = 0;

    if (g_every_second == gstate.time_now) {
        return;
    } else {
        g_every_second = gstate.time_now;
    }

    send_COMMs();
}

static char *format_pos(char *buf, const float *pos)
{
    char *cur = buf;
    for (int i = 0; i < DIM; i++) {
        if (i == 0) {
            cur += sprintf(cur, "%f", pos[i]);
        } else {
            cur += sprintf(cur, " %f", pos[i]);
        }
    }
    return buf;
}

static int console_handler(FILE *fp, int argc, char *argv[])
{
    char buf_pos[8 * DIM];

    #define MATCH(n, cmd) ((n) == argc && !strcmp(argv[0], (cmd)))

    if (MATCH(1, "h")) {
        fprintf(fp, "n: print neighbor table\n");
    } else if (MATCH(1, "i")) {
        fprintf(fp, "  own pos: %s\n", format_pos(buf_pos, g_own_pos));
    } else if (MATCH(1, "n")) {
        unsigned counter = 0;
        Neighbor *cur;
        Neighbor *tmp;

        fprintf(fp, "  sender_id addr updated bloom\n");
        HASH_ITER(hh, g_neighbors, cur, tmp) {
            fprintf(fp, "  0x%08x %s %s %s\n",
                cur->sender_id,
                str_addr(&cur->addr),
                str_duration(cur->last_updated, gstate.time_now),
                format_pos(buf_pos, cur->pos)
            );
            counter += 1;
        }
        fprintf(fp, "%u entries\n", counter);
    } else {
        return 1;
    }

    return 0;
}

static void init()
{
    vec_random_unit(&g_own_pos[0]);

    net_add_handler(-1, &periodic_handler);
}

void vivaldi_0_register()
{
    static const Protocol p = {
        .name = "vivaldi-0",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console = &console_handler,
    };

    protocols_register(&p);
}
