
#ifndef _MAIN_H
#define _MAIN_H

#include <time.h>

#define MAIN_SRVNAME "main"

typedef struct sockaddr_storage IP;
typedef struct sockaddr_in IP4;
typedef struct sockaddr_in6 IP6;

struct config {
	int is_running;
	time_t time_now;
	int use_syslog;
	int verbosity;
	int af;
};

extern struct config *gconf;

#endif // _MAIN_H
