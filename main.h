
#ifndef _MAIN_H
#define _MAIN_H

#include <time.h>
#include <stdint.h>
#include <netinet/in.h>

#define MAIN_SRVNAME "main"

struct address {
	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;
};

struct config {
	uint32_t id;
	const char *dev;
	int is_running;
	int drop_multicast;
	time_t time_now;
	int use_syslog;
	int verbosity;
};

extern struct config *gconf;

#endif // _MAIN_H
