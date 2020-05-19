
#ifndef _MAIN_H
#define _MAIN_H

#include <time.h>

#define MAIN_SRVNAME "main"

struct config {
	const char *dev;
	int is_running;
	int drop_multicast;
	time_t time_now;
	int use_syslog;
	int verbosity;
};

extern struct config *gconf;

#endif // _MAIN_H
