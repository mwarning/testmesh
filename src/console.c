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


// forward log output over (a single) remote connection
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
    for (size_t i = 0; i < len; i++) {
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

static int console_exec(int clientsock, FILE *fp, int argc, char *argv[])
{
    #define MATCH(n, cmd) ((n) == argc && !strcmp(argv[0], (cmd)))

    int ret = 0;

    if (argc > 0 && !strcmp(argv[0], "t")) {
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
            char *ptr = NULL;
            const char *end = argv[1] + strlen(argv[1]);
            uint32_t log_level = strtoul(argv[1], &ptr, 10);
            if (ptr != end || log_level > MAX_LOG_LEVEL) {
                fprintf(fp, "invalid log level");
            } else {
                gstate.log_level = log_level;
                fprintf(fp, "log level is now %u of %u\n", gstate.log_level, MAX_LOG_LEVEL);
            }
        } else {
            if (g_console_socket == -1) {
                g_console_socket = clientsock;
                fprintf(fp, "log to console enabled\n");
            } else if (g_console_socket == clientsock) {
                g_console_socket = -1;
                fprintf(fp, "log to console disabled\n");
            } else {
                fprintf(fp, "log goes to different remote console already\n");
            }
        }
    } else if (MATCH(1, "i")) {
        fprintf(fp, "protocol:   %s\n", gstate.protocol->name);
        fprintf(fp, "own id:     0x%08x\n", gstate.own_id);
        if (gstate.gateway_id_set) {
            fprintf(fp, "gateway id: 0x%08x\n", gstate.gateway_id);
        } else {
            fprintf(fp, "gateway id: none\n");
        }
        fprintf(fp, "process id: %u\n", (unsigned) getpid());
        fprintf(fp, "log level:  %u of %u\n", gstate.log_level, MAX_LOG_LEVEL);
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
            "v [log-level]           Toggle log to this console / change verbosity.\n"
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

    fprintf(fp, "================\n");

    return ret;
}

void console_client_handler(int rc, int clientsock)
{
    char request[256];
    char *argv[8];
    int argc;

    int ret = 0;
    FILE *fp;

    if (rc <= 0) {
        return;
    }

    fp = fdopen(dup(clientsock), "w");

    while (1) {
        int read_len = read(clientsock, request, sizeof(request));
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
        ret = console_exec(clientsock, fp, argc, argv);
    }

    if (fp) {
        fclose(fp);
    }

    // close connection
    if (ret == 1) {
        if (g_console_socket == clientsock) {
            g_console_socket = -1;
        }
        net_remove_handler(clientsock, &console_client_handler);
        close(clientsock);
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

    net_add_handler(clientsock, &console_client_handler);
}
