#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libgen.h> /* dirname() */

#include "main.h"
#include "log.h"
#include "unix.h"


static void shutdown_handler(int signo)
{
	// exit on second stop request
	if (gconf->is_running == 0) {
		exit(1);
	}

	gconf->is_running = 0;

	log_info("Shutting down...");
}

void unix_signals(void)
{
	struct sigaction sig_stop;
	struct sigaction sig_term;

	// STRG+C aka SIGINT => Stop the program
	sig_stop.sa_handler = shutdown_handler;
	sig_stop.sa_flags = 0;
	if ((sigemptyset(&sig_stop.sa_mask) == -1) || (sigaction(SIGINT, &sig_stop, NULL) != 0)) {
		log_error("Failed to set SIGINT handler: %s", strerror(errno));
		exit(1);
	}

	// SIGTERM => Stop the program gracefully
	sig_term.sa_handler = shutdown_handler;
	sig_term.sa_flags = 0;
	if ((sigemptyset(&sig_term.sa_mask) == -1) || (sigaction(SIGTERM, &sig_term, NULL) != 0)) {
		log_error("Failed to set SIGTERM handler: %s", strerror(errno));
		exit(1);
	}

	// ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);
}
