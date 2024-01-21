
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
static bool g_entry_removed = false;


// Set a socket non-blocking
int net_set_nonblocking(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

void net_add_handler(int fd, net_callback *cb)
{
	if (cb == NULL) {
		log_error("net_add_handler() Callback is null.");
		exit(1);
	}

	if (g_count == ARRAY_SIZE(g_cbs)) {
		log_error("net_add_handler() No more space for handlers.");
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
	if (cb == NULL) {
		log_error("net_remove_handler() callback is null");
		exit(1);
	}

	for (size_t i = 0; i < g_count; ++i) {
		if (g_cbs[i] == cb && g_fds[i].fd == fd) {
			// mark for removal in compress_entries()
			g_cbs[i] = NULL;
			g_entry_removed = true;
			return;
		}
	}

	log_error("net_remove_handler() handler not found");
	exit(1);
}

static void compress_entries()
{
	for (size_t i = 0; i < g_count; ++i) {
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
	bool call_all = false; // call all handlers
	uint64_t call_all_time = time_millis_now();

	// call all callbacks immediately
	for (size_t i = 0; i < g_count; i++) {
		g_cbs[i](-1, g_fds[i].fd);
	}

	while (gstate.is_running) {
		int rc = poll(g_fds, g_count, 1000);

		if (rc < 0) {
			if (gstate.is_running) {
				log_error("poll() %s", strerror(errno));
			}
			break;
		}

		gstate.time_now = time_millis_now();

		if ((call_all_time - gstate.time_now) >= 1000) {
			call_all = true;
			call_all_time = gstate.time_now;
		} else {
			call_all = false;
		}

		for (size_t i = 0; i < g_count; i++) {
			int revents = g_fds[i].revents;
			int fd = g_fds[i].fd;
			net_callback *cb = g_cbs[i];

			if (revents || call_all) {
				cb(revents, fd);
			}
		}

		if (g_entry_removed) {
			compress_entries();
			g_entry_removed = false;
		}
	}
}

void net_free(void)
{
	for (size_t i = 0; i < g_count; i++) {
		close(g_fds[i].fd);
	}

	g_count = 0;
}
