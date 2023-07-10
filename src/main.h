
#ifndef _MAIN_H
#define _MAIN_H

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "utils.h"
#include "interfaces.h"

#define MAIN_SRVNAME "testmesh"
#define PROGRAMM_VERSION "1.0.0"

#define MULTICAST_ADDR "ff12::114"
#define MULTICAST_PORT 4321
#define UNICAST_PORT 654

typedef struct {
    const char *name;
    void (*init)();
    void (*exit)();
    void (*tun_handler)(uint32_t dst_id, uint8_t *packet, size_t length); // receive IP frames from tun0
    void (*ext_handler_l2)(const Address *rvc, const Address *src, const Address *dst, uint8_t *packet, size_t length); // receive Ethernet frames
    void (*ext_handler_l3)(const Address *src_addr, uint8_t *packet, size_t length); // receive IP frames
    bool (*peer_handler)(const char *address, bool add);
    bool (*interface_handler)(uint32_t ifindex, bool add);
    bool (*console_handler)(FILE* file, const char *argv[]);
} Protocol;

void protocols_register(const Protocol *p);
const Protocol *protocols_find(const char *protocol);
void protocols_print(FILE *fd);

struct state {
    const Protocol *protocol;

    // sockets
    int sock_help; // helper socket used to communicate with the kernel
    int sock_console; // unix socket
    int sock_udp; // also used to send mcast
#ifdef MULTICAST
    int sock_mcast_receive;
#endif
    uint16_t ether_type;
    enum FIND_INTERFACES find_interfaces;

    uint32_t gateway_id;
    bool gateway_id_set;
    uint32_t own_id;
    bool own_id_set;

    bool do_fork;
    // state
    bool is_running;
    bool disable_stdin;
    time_t time_now;
    time_t time_started;
#ifdef MULTICAST
    // local network discovery address
    struct sockaddr_in6 mcast_addr;
#endif
    // listen address for unicast packets
    struct sockaddr_in6 ucast_addr;

    bool enable_ipv4;
    bool enable_ipv6;

    // tun0 - entry to the mesh
    const char *tun_name;
    int tun_fd;

    bool tun_setup;
    uint16_t tun_setup_ipv4_mtu;

    const char *control_socket_path;

    // settings
    bool log_to_syslog;
    bool log_to_terminal;
    FILE* log_to_file;
    bool log_to_socket;
    bool log_time;
    uint8_t log_level;
};

extern struct state gstate;

#endif // _MAIN_H
