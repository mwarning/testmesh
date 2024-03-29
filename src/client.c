#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <stddef.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <math.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "unix.h"
#include "client.h"


/*
 * A separate program part to control the routing daemon.
 */

int g_client_sock = -1;
bool g_shutdown_after_reply = false;

void client_usage(const char *program_name)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s [-c <control-socket-path>] [<command-to-send>]\n"
        "\n"
        "-c <path>       Path to control socket (Default: "CLIENT_DEFAULT_SOCKET").\n"
        "-k              Do not close terminal if command are passed on the command line.\n"
        "-h              Prints this help text.\n"
        "\n"
        "If no command is given as argument, then an interactive shell will be started.\n",
        program_name
    );
}

// read from unix socket and write to stdout
void client_handler_out(int rc, int fd)
{
    char request[1024];
    bool ret = false;

    if (rc <= 0) {
        return;
    }

    while (true) {
        int read_len = read(fd, request, sizeof(request));
        //printf("read_len: %d\n", read_len);
        if (read_len == 0) {
            // connection was closed by the remote
            ret = true;
            break;
        }

        if (read_len == -1) {
            // all read
            break;
        }

        fprintf(stdout, "%.*s", read_len, request);
    }

    // close connection
    if (ret || g_shutdown_after_reply) {
        gstate.is_running = false;
    }
}

// read from stdin and write to unix socket
void client_handler_in(int rc, int fd)
{
    char request[1024];

    if (rc <= 0) {
        return;
    }

    ssize_t read_len = read(fd, request, sizeof(request));
    // read from STDIN
    if (read_len < 0) {
        fprintf(stderr, "read() %s\n", strerror(errno));
        return;
    }

    // write to unix socket
    ssize_t write_len = write(g_client_sock, request, read_len);
    if (write_len < 0) {
        fprintf(stderr, "write(): %s\n", strerror(errno));
        return;
    }
}

int client_main(int argc, char *argv[])
{
    const char *socket_path = CLIENT_DEFAULT_SOCKET;
    char *command = NULL; // command from console
    bool no_shutdown_after_reply = false;

    int option;
    while ((option = getopt(argc, argv, "c:hk")) > 0) {
        switch(option) {
            case 'c':
                socket_path = optarg;
                break;
            case 'h':
                client_usage(argv[0]);
                return EXIT_SUCCESS;
            case 'k':
                no_shutdown_after_reply = true;
                break;
            default:
                log_error("Unknown option %c", option);
                client_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

	if (socket_path == NULL) {
		fprintf(stderr, "No socket path given.\n");
		return EXIT_FAILURE;
	}

    if (argc > optind) {
        // concatenate extra args
        int len = 0;
        for (size_t i = optind; i < argc; i += 1) {
          len += strlen(argv[i]) + 1;
        }

        command = (char*) malloc(len + 1);
        command[0] = '\0';
        for (size_t i = optind; i < argc; i += 1) {
           strcat(command, argv[i]);
           strcat(command, " ");
        }
    }

    g_client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa_un = {
        .sun_family = AF_UNIX
    };
    strncpy(sa_un.sun_path, socket_path, (sizeof(sa_un.sun_path) - 1));

    if (connect(g_client_sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
        fprintf(stderr, "Failed to connect: %s (%s)\n", strerror(errno), socket_path);
        return EXIT_FAILURE;
    }

    unix_signals();

    net_add_handler(g_client_sock, &client_handler_out);

    if (command) {
        if (no_shutdown_after_reply) {
            g_shutdown_after_reply = false;
        } else {
            g_shutdown_after_reply = true;
        }

    	// write to socket
        ssize_t write_len = write(g_client_sock, command, strlen(command));
        if (write_len < 0) {
            fprintf(stderr, "Failed to write: %s\n", strerror(errno));
        }

        // allow further input from stdin
        if (no_shutdown_after_reply) {
            net_add_handler(STDIN_FILENO, &client_handler_in);
        }
    } else {
        g_shutdown_after_reply = false;
        // allow further input from stdin
        net_add_handler(STDIN_FILENO, &client_handler_in);
    }

    net_loop();

    return EXIT_SUCCESS;
}
