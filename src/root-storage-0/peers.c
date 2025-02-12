
#include "../main.h"
#include "../log.h"

#include "packets.h"
#include "neighbors.h"
#include "peers.h"

static Peer *g_peers = NULL;

Peer *peers_all()
{
	return g_peers;
}

void peers_add(const char *hostname)
{
    Peer *peer = g_peers;
    Peer *prev = NULL;

    if (hostname == NULL || strlen(hostname) >= 64) {
        return;
    }

    // check for duplicate
    while (peer) {
        if (0 == strcmp(hostname, &peer->hostname[0])) {
            return;
        }
        prev = peer;
        peer = peer->next;
    }

    peer = (Peer*) calloc(1, sizeof(Peer));
    memcpy(&peer->hostname[0], hostname, strlen(hostname));

    if (g_peers == NULL) {
        g_peers = peer;
    } else {
        prev->next = peer;
    }
}

void peers_del(const char *hostname)
{
    Peer *peer = g_peers;
    Peer *prev = NULL;

    // check for duplicate
    while (peer) {
        if (0 == strcmp(hostname, &peer->hostname[0])) {
            if (prev) {
                prev->next = peer->next;
            } else {
                g_peers = peer->next;
            }

            free(peer);
            return;
        }
        prev = peer;
        peer = peer->next;
    }
}

// add static peers 
void peers_periodic()
{
    static uint64_t last_check_ms = 0;
    static uint32_t check_interval_ms = 200; // start value milliseconds

    if (g_peers && (last_check_ms == 0 || (gstate.time_now - last_check_ms) > check_interval_ms)) {
        last_check_ms = gstate.time_now;
        if (check_interval_ms < (24 * 60 * 60 * 1000)) {
            check_interval_ms *= 2;
        }

        log_debug("peers_periodic() do now, next peer ping in %s", str_time(check_interval_ms));

        PING ping = {
            .type = TYPE_PING,
            .seq_num = packets_next_sequence_number(),
        };

        uint32_t pings_send = 0;
        Peer *peer = g_peers;
        while (peer) {
            if (!address_is_zero(&peer->address) && !neighbors_find(&peer->address)) {
                // peer not resolved and not connected
                bool resolved = false;
                int af = gstate.af;
                if (af == AF_UNSPEC || af == AF_INET6) {
                    if (addr_parse((struct sockaddr *) &peer->address, &peer->hostname[0], STR(UNICAST_UDP_PORT), AF_INET6)) {
                        log_debug("peer: send ping to %s", str_addr(&peer->address));
                        send_ucast_wrapper(&peer->address, &ping, sizeof(PING));
                        resolved = true;
                        pings_send += 1;
                    }
                }

                if (af == AF_UNSPEC || af == AF_INET) {
                    if (addr_parse((struct sockaddr *) &peer->address, &peer->hostname[0], STR(UNICAST_UDP_PORT), AF_INET)) {
                        log_debug("peer: send ping to %s", str_addr(&peer->address));
                        send_ucast_wrapper(&peer->address, &ping, sizeof(PING));
                        resolved = true;
                        pings_send += 1;
                    }
                }

                if (!resolved) {
                    log_warning("peer: failed to resolve %s", &peer->hostname[0]);
                }
            }
            peer = peer->next;
        }
    }
}
