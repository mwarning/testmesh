
#ifndef _MAIN_H
#define _MAIN_H

#include <time.h>

#define MAIN_SRVNAME "main"

struct config {
	int is_running;
	time_t time_now;
	int use_syslog;
	int verbosity;
};

extern struct config *gconf;

#endif // _MAIN_H
