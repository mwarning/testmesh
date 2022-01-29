
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
#include <time.h> // time()
#include <poll.h>
#include <fcntl.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "net.h"


static struct pollfd g_fds[16] = { 0 };
static net_callback* g_cbs[16] = { NULL };
static int g_count = 0;
static int g_entry_removed = 0;


// Set a socket non-blocking
int net_set_nonblocking(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

void net_add_handler(int fd, net_callback *cb)
{
	if (cb == NULL) {
		log_error("Invalid arguments.");
		exit(1);
	}

	if (g_count == ARRAY_NELEMS(g_cbs)) {
		log_error("No more space for handlers.");
		exit(1);
	}

	if (fd >= 0) {
		net_set_nonblocking(fd);
	}

	g_cbs[g_count] = cb;
	g_fds[g_count].fd = fd;
	g_fds[g_count].events = POLLIN;

	g_count += 1;
}

void net_remove_handler(int fd, net_callback *cb)
{
	int i;

	if (cb == NULL) {
		log_error("Invalid arguments.");
		exit(1);
	}

	for (i = 0; i < g_count; i++) {
		if (g_cbs[i] == cb && g_fds[i].fd == fd) {
			// mark for removal in compress_entries()
			g_cbs[i] = NULL;
			g_entry_removed = 1;
			return;
		}
	}

	log_error("Handler not found to remove.");
	exit(1);
}

static void compress_entries()
{
	for (int i = 0; i < g_count; i += 1) {
		while (g_cbs[i] == NULL && i < g_count) {
			g_count -= 1;
			g_cbs[i] = g_cbs[g_count];
			g_fds[i].fd = g_fds[g_count].fd;
			g_fds[i].events = g_fds[g_count].events;
		}
	}
}

void net_loop(void)
{
	time_t n;
	int all;
	int rc;

	while (gstate.is_running) {
		rc = poll(g_fds, g_count, 1000);

		if (rc < 0) {
			if (gstate.is_running) {
				log_error("poll(): %s", strerror(errno));
			}
			break;
		}

		n = time(NULL);
		all = (n > gstate.time_now);
		gstate.time_now = n;

		for (int i = 0; i < g_count; i++) {
			int revents = g_fds[i].revents;
			int fd = g_fds[i].fd;
			net_callback *cb = g_cbs[i];

			if (cb && (revents || all)) {
				cb(revents, fd);
			}
		}

		if (g_entry_removed) {
			compress_entries();
			g_entry_removed = 0;
		}
	}
}

void net_free(void)
{
	for (int i = 0; i < g_count; i++) {
		close(g_fds[i].fd);
	}

	g_count = 0;
}
