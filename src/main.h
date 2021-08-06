
#ifndef _MAIN_H
#define _MAIN_H

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define MAIN_SRVNAME "mesh"
#define MULTICAST_ADDR "ff12::114"
#define MULTICAST_PORT 4321
#define UNICAST_PORT 654


typedef struct {
    const char *name;
    void (*init)();
    void (*tun_handler)(int events, int fd); // packet from the local virtual interface
    void (*ext_handler_l2)(int events, int fd); // receive Ethernet frames
    void (*ext_handler_l3)(int events, int fd); // receive IP frames
    int (*add_peer)(FILE* fp, const char *str);
    int (*console)(FILE* file, int argc, char *argv[]);
} Protocol;

void register_protocol(const Protocol *p);
const Protocol *find_protocol(const char *protocol);

struct state {
    const Protocol *protocol;

	// sockets
	int sock_help; // helper socket used to communicate with the kernel
	int sock_console; // unix socket
	int sock_udp; // also used to send mcast
	int sock_mcast_receive;
	uint16_t ether_type;

	int do_fork;
	// state
	int is_running;
	int disable_stdin;
	time_t time_now;
	time_t time_started;

	// local network discovery address
	struct sockaddr_in6 mcast_addr;

	// listen address for unicast packets
	struct sockaddr_in6 ucast_addr;

	// tun0 - entry to the mesh
	const char *tun_name;
	int tun_fd;
	struct in6_addr tun_addr;
	const char *control_socket_path;

	// settings
	int log_to_syslog;
	int log_to_terminal;
	FILE* log_to_file;
	int log_to_socket;
	int log_timestamp;
	int log_verbosity;
};

extern struct state gstate;

#endif // _MAIN_H
