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
#include <inttypes.h>

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

/*
* Provide an interactive console via stdin and unix socket.
*/

// forward log output over (a single) remote connection
static int g_console_socket = -1;

static const char *g_usage =
    "i                       General information.\n"
    "t [<show-num>]          Show traffic statistics\n"
    "interfaces              List all used interfaces.\n"
    "interface-add <ifname>  Add interface.\n"
    "interface-del <ifname>  Remove interface.\n"
    "l                       Enable/Disable log to console.\n"
    "ll <log-level>          Toggle log to this console / change verbosity.\n"
    "q                       Close this console.\n"
    "h                       Show this help.\n";

// output log messages to console as well
void console_log_message(const char *message)
{
    if (g_console_socket >= 0) {
        write(g_console_socket, message, strlen(message));
    }
}

enum {
    oHelp,
    oTraffic,
    oQuit,
    oInterfaceAdd,
    oInterfaceDel,
    oInterfaces,
    oLogging,
    oLogLevel,
    oInfo,
};

static const option_t g_options[] = {
    {"h", 1, oHelp},
    {"t", 1, oTraffic},
    {"q", 1, oQuit},
    {"interface-add", 2, oInterfaceAdd},
    {"interface-del", 2, oInterfaceDel},
    {"interfaces", 1, oInterfaces},
    {"l", 1, oLogging},
    {"ll", 2, oLogLevel},
    {"i", 1, oInfo},
    {NULL, 0, 0}
};

static bool is_stdin(int fd)
{
    return fd == STDIN_FILENO && !gstate.do_fork;
}

static bool console_exec(int clientsock, FILE *fp, char *line)
{
    const char *argv[8];
    int argc = setargs(&argv[0], ARRAY_SIZE(argv), line);

    if (argc == 0) {
        // Print usage
        fprintf(fp, "%s", g_usage);
        return false;
    }

    const option_t *option = find_option(g_options, argv[0]);

    if (option == NULL) {
        // call protocol specific console handler
        if (gstate.protocol->console_handler == NULL || !gstate.protocol->console_handler(fp, argc, argv)) {
            fprintf(fp, "Unknown command. Use 'h' for help.\n");
        }
        return false;
    }

    if (option->num_args != argc) {
        fprintf(fp, "Unexpected number of arguments.\n");
        return false;
    }

    switch (option->code) {
    case oTraffic:
        traffic_debug(fp, argv);
        break;
    case oInterfaceAdd:
        if (interface_add(argv[1])) {
            fprintf(fp, "done\n");
        } else {
            fprintf(fp, "failed\n");
        }
        break;
    case oInterfaceDel:
        if (interface_del(argv[1])) {
            fprintf(fp, "done\n");
        } else {
            fprintf(fp, "failed\n");
        }
        break;
    case oInterfaces:
        interfaces_debug(fp);
        break;
    case oLogging:
        if (is_stdin(clientsock)) {
            // local terminal session (and stdin not closed)
            if (gstate.log_to_terminal) {
                gstate.log_to_terminal = false;
                fprintf(fp, "log to terminal disabled\n");
            } else {
                gstate.log_to_terminal = true;
                fprintf(fp, "log to terminal enabled\n");
            }
        } else {
            // console session via socket (testmesh-ctl)
            if (g_console_socket == clientsock || g_console_socket == -1) {
                if (g_console_socket == clientsock) {
                    g_console_socket = -1;
                    gstate.log_to_socket = false;
                    fprintf(fp, "log to console disabled\n");
                } else {
                    g_console_socket = clientsock;
                    gstate.log_to_socket = true;
                    fprintf(fp, "log to console enabled\n");
                }
            } else {
                fprintf(fp, "log goes to different remote console already (only one is supported)\n");
            }
        }
        break;
    case oLogLevel:
        uint8_t log_level = log_level_parse(argv[1]);
        if (log_level_str(log_level) == NULL) {
            fprintf(fp, "invalid log level\n");
        } else {
            gstate.log_level = log_level;
            fprintf(fp, "log level is now %s\n", log_level_str(gstate.log_level));
        }
        break;
    case oQuit:
        // close console
        return true;
    case oInfo:
        fprintf(fp, "protocol:        %s\n", gstate.protocol->name);

        if (gstate.own_id_set) {
            fprintf(fp, "own id:          0x%08x\n", gstate.own_id);
        } else {
            fprintf(fp, "own id:          none\n");
        }

        if (gstate.gateway_id_set) {
            fprintf(fp, "gateway id:      0x%08x\n", gstate.gateway_id);
        } else {
            fprintf(fp, "gateway id:      none\n");
        }

        fprintf(fp, "process id:      %u\n", (unsigned) getpid());
        fprintf(fp, "log level:       %u of %u\n", gstate.log_level, MAX_LOG_LEVEL);
        fprintf(fp, "uptime:          %s\n", str_since(gstate.time_started));
        fprintf(fp, "find interfaces: %s\n", str_find_interfaces(gstate.find_interfaces));

        if (gstate.tun_name) {
            fprintf(fp, "tun device:      %s\n", gstate.tun_name);
            fprintf(fp, "tun traffic:     %s (%"PRIu64") / %s (%"PRIu64")\n",
                str_bytes(tun_read_bytes()), tun_read_count(),
                str_bytes(tun_write_bytes()), tun_write_count());
        }

        if (gstate.protocol->console_handler) {
            gstate.protocol->console_handler(fp, argc, argv);
        }
        break;
    case oHelp:
        fprintf(fp, "%s", g_usage);
        break;
    }

    return false;
}

void console_client_handler(int rc, int clientsock)
{
    char request[256];
    bool quit = false;
    FILE *fp;

    if (rc <= 0) {
        return;
    }

    fp = fdopen(dup(clientsock), "w");

    while (!quit) {
        ssize_t read_len = read(clientsock, request, sizeof(request));
        if (read_len == 0) {
            // connection was closed by the remote
            quit = true;
            break;
        }

        if (read_len < 0) {
            // read error
            break;
        }

        request[read_len] = '\0';
        quit = console_exec(clientsock, fp, request);
    }

    if (fp) {
        fclose(fp);
    }

    // close connection
    if (quit) {
        if (g_console_socket == clientsock) {
            g_console_socket = -1;
        }
        net_remove_handler(clientsock, &console_client_handler);
        close(clientsock);
    }
}

void console_server_handler(int rc, int serversock)
{
    if (rc <= 0) {
        return;
    }

    struct sockaddr_un addr = {0};
    socklen_t addrlen = sizeof(addr);
    int clientsock = accept(serversock, (struct sockaddr *) &addr, &addrlen);
    if (clientsock < 0) {
        log_error("accept(): %s", strerror(errno));
        return;
    }

    net_add_handler(clientsock, &console_client_handler);
}

bool console_setup()
{
    if (gstate.control_socket_path) {
        unix_create_unix_socket(gstate.control_socket_path, &gstate.sock_console);
        net_add_handler(gstate.sock_console, &console_server_handler);
    }

    return true;
}

void console_free()
{
    if (gstate.control_socket_path) {
        unix_remove_unix_socket(gstate.control_socket_path, gstate.sock_console);
    }
}
