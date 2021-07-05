#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <stddef.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <math.h>

#include "../log.h"
#include "../utils.h"
#include "../net.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"

#include "routing.h"

#define DIM 3

enum {
    TYPE_DATA
};

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    float pos[DIM];
    uint16_t length; // might not be needed
    uint8_t payload[2000];
} DATA;

static void vec_mul(float ret[DIM], const float a[DIM], float b)
{
	for (int i = 0; i < DIM; i += 1) {
		ret[i] = a[i] * b;
	}
}

static void vec_sub(float ret[DIM], const float a[DIM], const float b[DIM])
{
	for (int i = 0; i < DIM; i += 1) {
		ret[i] = a[i] - b[i];
	}
}

static void vec_add(float ret[DIM], const float a[DIM], const float b[DIM])
{
	for (int i = 0; i < DIM; i += 1) {
		ret[i] = a[i] + b[i];
	}
}

static void vec_copy(float ret[DIM], const float a[DIM])
{
	for (int i = 0; i < DIM; i += 1) {
		ret[i] = a[i];
	}
}

static float vec_len(const float a[DIM])
{
	float sum = 0;
	for (int i = 0; i < DIM; i += 1) {
		sum += a[i] * a[i];
	}

	return sqrt(sum);
}

static int is_near_null(const float v[DIM], float eta)
{
	for (int i = 0; i < DIM; i += 1) {
		if (v[i] >= eta && v[i] <= -eta) {
			return 0;
		}
	}

	return 1;
}

static void random_unit(float ret[DIM])
{
	for (int i = 0; i < DIM; i += 1) {
		ret[i] = (float) (double) rand();
	}

	float len = vec_len(ret);

	for (int i = 0; i < DIM; i += 1) {
		ret[i] /= len;
	}
}

// Vivaldi algorithm
static void vivaldi_update(float local_pos[DIM], float *local_error, float pos[DIM], float remote_error, float rtt)
{
	/*
	float error_sensitivity_adj = 0.25;
	float position_sensitivity_adj = 0.25;
	float local_error = 1000;

	float balance_error = local_error / (local_error + remote_error);

	rel_error = 
	*/

//fn vivaldi_update(&mut self, pos: &VVec, remote_error: f32, rtt: f32) {
	//let rtt = self.rtt;
	float ce = 0.25;
	float cc = 0.25;

	// w = e_i / (e_i + e_j)
	float w = 1.0;

	if (*local_error > 0.0 && remote_error > 0.0) {
		w = *local_error / (*local_error + remote_error);
	}

	// x_i - x_j
	float ab[DIM];
	vec_sub(ab, local_pos, pos);

	// rtt - |x_i - x_j|
	float re = rtt - vec_len(ab);

	// e_s = ||x_i - x_j| - rtt| / rtt
	float es = abs(re) / rtt;

	// e_i = e_s * c_e * w + e_i * (1 - c_e * w)
	*local_error = es * ce * w + *local_error * (1.0 - ce * w);

	// ∂ = c_c * w
	float d = cc * w;

	// Choose random direction if both positions are identical
	float direction[DIM];
	if (is_near_null(ab, 0.01)) {
		//println!("random direction");
		random_unit(direction);
	} else {
		vec_copy(direction, ab);
	}

	//println!("old pos: {}, {} {} {}", state.pos, direction, w, re);

	// x_i = x_i + ∂ * (rtt - |x_i - x_j|) * u(x_i - x_j)
	float tmp[DIM];
	vec_mul(tmp, direction, d * re);
	vec_add(local_pos, local_pos, tmp);

	//println!("new pos: {}", self.pos);
}

// read traffic from tun0 and send to peers
static void tun_handler(int events, int fd)
{
    DATA data = {
        .type = TYPE_DATA,
    };

    if (events <= 0) {
        return;
    }

    while (1) {
        int read_len = read(fd, &data.payload[0], sizeof(data.payload));
        if (read_len <= 0) {
            break;
        }

        int ip_version = (data.payload[0] >> 4) & 0x0f;

        if (ip_version != 6) {
            log_debug("unhandled packet protocol version (IPv%d) => drop", ip_version);
            continue;
        }

        if (read_len < 24) {
            log_debug("payload too small (%d) => drop", read_len);
            continue;
        }

        // IPv6 packet
        int payload_length = ntohs(*((uint16_t*) &data.payload[4]));
        struct in6_addr *saddr = (struct in6_addr *) &data.payload[8];
        struct in6_addr *daddr = (struct in6_addr *) &data.payload[24];

        if (IN6_IS_ADDR_MULTICAST(daddr)) {
            // no support for multicast traffic
            continue;
        }

        // some id we want to send data to
        uint32_t dst_id = 0;
        id_get6(&dst_id, daddr);

        log_debug("read %d from %s for %04x", read_len, gstate.tun_name, dst_id);

/*
        if (dst_id == g_own_id) {
            log_warning("send packet to self => drop packet");
            continue;
        }
        data.seq_num = g_sequence_number++;
        data.src_id = g_own_id;
        data.dst_id = dst_id;
        data.length = read_len;

        send_mcasts(&data, offsetof(DATA, payload) + read_len);
*/
    }
}

static void ext_handler(int events, int fd)
{
    struct sockaddr_storage from_addr = {0};
    struct sockaddr_storage to_addr = {0};
    uint8_t buffer[sizeof(DATA)];
    ssize_t recv_len;
    int ifindex = 0;

    if (events <= 0) {
        return;
    }

    recv_len = recv6_fromto(
        fd, buffer, sizeof(buffer), 0, &ifindex, &from_addr, &to_addr);

    if (recv_len <= 0) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }

    if (fd == gstate.sock_mcast_receive) {
        log_debug("got mcast %s => %s (%s)", str_addr(&from_addr), str_addr(&to_addr), str_ifindex(ifindex));
    } else {
        log_debug("got ucast %s => %s (%s)", str_addr(&from_addr), str_addr(&to_addr), str_ifindex(ifindex));
    }

/*
    switch (buffer[0]) {
    case TYPE_DATA:
        //handle_DATA(ifindex, &from_addr, (DATA*) buffer, recv_len);
        break;
    default:
        log_warning("Unknown packet type %u from %s (%s)", (unsigned) buffer[0], str_addr(&from_addr), str_ifindex(ifindex));
    }
*/
}

static void init()
{
}

void vivaldi_0_register()
{
    static const Protocol p = {
        .name = "vivaldi-0",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler = &ext_handler
    };

    register_protocol(&p);
}
