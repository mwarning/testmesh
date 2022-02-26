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
#include <stdarg.h>

#include "log.h"
#include "utils.h"
#include "net.h"
#include "conf.h"
#include "unix.h"
#include "console.h"
#include "interfaces.h"
#include "main.h"
#include "tun.h"
#include "traffic.h"


// forward console output over console socket / unix domain socket
static int g_console_socket = -1;

// output log messages to console as well
void console_log_message(const char *message)
{
    if (g_console_socket >= 0) {
        write(g_console_socket, message, strlen(message));
    }
}

static int tokenizer(char *argv[], int argc_max, char *input)
{
    int argc = 0;

    char *p = NULL;
    const int len = strlen(input);
    for (int i = 0; i < len; i++) {
        if (input[i] <= ' ') {
            if (p) {
                if (argc == argc_max) {
                    log_warning("too many tokens\n");
                    return 0;
                }
                argv[argc++] = p;
                p = NULL;
            }
            input[i] = 0;
        } else if (p == NULL) {
            p = &input[i];
        }
    }

    if (p) {
        if (argc == argc_max) {
            log_warning("too many tokens\n");
            return 0;
        }
        argv[argc++] = p;
    }

    return argc;
}

static int console_exec(FILE *fp, int argc, char *argv[])
{
    #define MATCH(n, cmd) ((n) == argc && !strcmp(argv[0], (cmd)))

    int ret = 0;

    if (argc && !strcmp(argv[0], "t")) {
        traffic_debug(fp, argc, argv);
    } else if (MATCH(2, "peer-add")) {
        if (gstate.protocol->add_peer) {
            gstate.protocol->add_peer(fp, argv[1]);
        } else {
            fprintf(fp, "not supported by protocol %s\n", gstate.protocol->name);
        }
    } else if (MATCH(1, "q")) {
        // close console
        ret = 1;
    } else if (MATCH(2, "interface-add")) {
        interface_add(argv[1]);
    } else if (MATCH(2, "interface-del")) {
        interface_del(argv[1]);
    } else if (MATCH(1, "interfaces")) {
        interfaces_debug(fp);
    } else if (MATCH(1, "v") || MATCH(2, "v")) {
        if (argc == 2) {
            gstate.log_level = atoi(argv[1]);
        } else {
            gstate.log_level += 1;
        }
        gstate.log_level %= (MAX_LOG_LEVEL + 1);
        fprintf(fp, "log level is now %u\n", gstate.log_level);
    } else if (MATCH(1, "i")) {
        fprintf(fp, "protocol:   %s\n", gstate.protocol->name);
        fprintf(fp, "own id:     0x%08x\n", gstate.own_id);
        if (gstate.gateway_id_set) {
            fprintf(fp, "gateway id: 0x%08x\n", gstate.gateway_id);
        } else {
            fprintf(fp, "gateway id: none\n");
        }
        fprintf(fp, "process id: %u\n", (unsigned) getpid());
        fprintf(fp, "log level:  %u\n", gstate.log_level);
        fprintf(fp, "uptime:     %s\n", str_ago(gstate.time_started));
        if (gstate.tun_name) {
            fprintf(fp, "tun device: %s\n", gstate.tun_name);
            fprintf(fp, "tun read:   %s (%s/s)\n",
                str_bytes(tun_read_total()), str_bytes(tun_read_speed()));
            fprintf(fp, "tun write:  %s (%s/s)\n",
                str_bytes(tun_write_total()), str_bytes(tun_write_speed()));
        }
        if (gstate.protocol->console) {
            gstate.protocol->console(fp, argc, argv);
        }
    } else if (MATCH(1, "h")) {
        fprintf(fp,
            "i                       General information.\n"
            "t [<show-num>]          Show traffic statistics\n"
            "interfaces              List all used interfaces.\n"
            "interface-add <ifname>  Add interface.\n"
            "interface-del <ifname>  Remove interface.\n"
            "peer-add <address>      Add peer via IP address.\n"
            "v [log-level]           Increase verbosity.\n"
            "q                       Close this console.\n"
            "h                       Show this help.\n"
        );

        if (gstate.protocol->console) {
            gstate.protocol->console(fp, argc, argv);
        }
    } else {
        int rc = 1;

        // call protocol specific console handler
        if (gstate.protocol->console) {
            rc = gstate.protocol->console(fp, argc, argv);
        }

        if (rc != 0) {
            fprintf(fp, "Unknown command. Use 'h' for help.\n");
        }
    }

    return ret;
}

void console_client_handler(int rc, int fd)
{
    char request[256];
    char *argv[8];
    int argc;

    int ret = 0;
    FILE *fp;

    if (rc <= 0) {
        return;
    }

    fp = fdopen(dup(fd), "w");

    while (1) {
        int read_len = read(fd, request, sizeof(request));
        if (read_len == 0) {
            // connection was closed by the remote
            ret = 1;
            break;
        }

        if (read_len < 0) {
            // read error
            break;
        }

        request[read_len] = '\0';
        argc = tokenizer(argv, ARRAY_NELEMS(argv), request);
        ret = console_exec(fp, argc, argv);
    }

    if (fp) {
        fclose(fp);
    }

    // close connection
    if (ret == 1) {
        if (g_console_socket == fd) {
            g_console_socket = -1;
        }
        net_remove_handler(fd, &console_client_handler);
        close(fd);
    }
}

void console_server_handler(int rc, int serversock)
{
    socklen_t addrlen;
    int clientsock;
    struct sockaddr_un addr;

    if (rc <= 0) {
        return;
    }

    addrlen = sizeof(addr);
    clientsock = accept(serversock, (struct sockaddr *) &addr, &addrlen);
    if (clientsock < 0) {
        log_error("accept(): %s", strerror(errno));
        return;
    }

    // how how to be able to log to clientsock??
    g_console_socket = clientsock;
    net_add_handler(clientsock, &console_client_handler);
}
