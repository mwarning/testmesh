
#ifndef _MAIN_H
#define _MAIN_H

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define MAIN_SRVNAME "mesh"

void send_ucast(const struct sockaddr_storage *addr, const void *data, int data_len);
const char *verbosity_str(int verbosity);

typedef struct {
    const char *name;
    void (*init)();
    void (*tun_handler)(int events, int fd); // packet from the local virtual interface
    void (*ext_handler)(int events, int fd); // remove external unicast/multicast packet
    int (*add_peer)(FILE* fp, const char *str);
    int (*console)(FILE* file, const char* cmd);
} Protocol;

void register_protocol(const Protocol *p);

struct state {
    const Protocol *protocol;

	// sockets
	int sock_help;
	int sock_udp; // also used to send mcast
	int sock_mcast_receive;
	int sock_console;

	// state
	int is_running;
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
