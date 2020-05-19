
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h> // close()
#include <net/if.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "net.h"


static struct pollfd g_fds[16] = { { .fd = -1, .events = POLLIN, .revents = 0 } };
static net_callback* g_cbs[16] = { NULL };


// Set a socket non-blocking
int net_set_nonblocking(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

void net_add_handler(int fd, net_callback *cb)
{
	int i;

	if (cb == NULL) {
		log_error("Invalid arguments.");
		exit(1);
	}

	for (i = 0; i < ARRAY_SIZE(g_cbs); i++) {
		if (g_cbs[i] == NULL) {
			g_cbs[i] = cb;
			g_fds[i].fd = fd;
			g_fds[i].events = POLLIN;
			return;
		}
	}

	log_error("No more space for handlers.");
	exit(1);
}

void net_remove_handler(int fd, net_callback *cb)
{
	int i;

	if (cb == NULL) {
		fprintf(stderr, "Invalid arguments.");
		exit(1);
	}

	for (i = 0; i < ARRAY_SIZE(g_cbs); i++) {
		if (g_cbs[i] == cb && g_fds[i].fd == fd) {
			g_cbs[i] = NULL;
			g_fds[i].fd = -1;
			return;
		}
	}

	log_error("Handler not found to remove.");
	exit(1);
}

void net_loop(void)
{
	time_t n;
	int all;
	int rc;
	int i;

	while (gconf->is_running) {
		rc = poll(g_fds, ARRAY_SIZE(g_fds), 1000);

		if (rc < 0) {
			//log_error("poll(): %s", strerror(errno));
			break;
		}

		n = time(NULL);
		all = (n > gconf->time_now);
		gconf->time_now = n;

		for (i = 0; i < ARRAY_SIZE(g_cbs); i++) {
			if (g_cbs[i]) {
				int revents = g_fds[i].revents;
				if (revents || all) {
					g_cbs[i](revents, g_fds[i].fd);
				}
			}
		}
	}
}

void net_free(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(g_cbs); i++) {
		g_cbs[i] = NULL;
		close(g_fds[i].fd);
		g_fds[i] = (struct pollfd){ .fd = -1, .events = POLLIN, .revents = 0 };
	}
}
