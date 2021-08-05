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

static void debug_ip_addresses(FILE *fp, const char *ifname)
{
    struct ifaddrs *ifa;
    struct ifaddrs *ifaddrs;
    char addr[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddrs) == -1) {
        log_error("getifaddrs() %s", strerror(errno));
        exit(1);
    }

    ifa = ifaddrs;
    while (ifa) {
        if (ifa->ifa_addr && 0 == strcmp(ifa->ifa_name, ifname)) {
            int sa_family = ifa->ifa_addr->sa_family;

            if (sa_family == AF_INET) {
                // create IPv4 string
                struct sockaddr_in *in = (struct sockaddr_in*) ifa->ifa_addr;
                inet_ntop(AF_INET, &in->sin_addr, addr, sizeof(addr));
                fprintf(fp, "     %s\n", addr);
            }

            if (sa_family == AF_INET6) {
                // create IPv6 string
                struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifa->ifa_addr;
                inet_ntop(AF_INET6, &in6->sin6_addr, addr, sizeof(addr));
                fprintf(fp, "    %s\n", addr);
            }
        }
        ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaddrs);
}

static void print_help(FILE *fp)
{
    fprintf(fp,
        "i: show general information\n"
        "add-peer <address>\n"
        "q: close this console\n"
        "v: toggle verbosity\n"
        "h: show this help\n"
    );

    if (gstate.protocol->console) {
        gstate.protocol->console(fp, "h\n");
    }
}

static int console_exec(FILE *fp, const char *request)
{
    char addr[32];
    char ifname[32];
    char verbosity[32];
    char d; // dummy marker
    int ret = 0;

    if (sscanf(request, " t%c", &d) == 1) {
        traffic_debug(fp);
    } else if (sscanf(request, " add-peer %s %c", addr, &d) == 2) {
        if (gstate.protocol->add_peer) {
            gstate.protocol->add_peer(fp, addr);
        } else {
            fprintf(fp, "not supported by protocol %s\n", gstate.protocol->name);
        }
    } else if (sscanf(request, " q%c", &d) == 1) {
        // close console
        ret = 1;
    } else if (sscanf(request, " interface-add %30s", &ifname[0]) == 1) {
        interface_add(ifname);
    } else if (sscanf(request, " interface-del %30s", &ifname[0]) == 1) {
        interface_del(ifname);
    } else if (sscanf(request, " interfaces %c", &d) == 1) {
        interfaces_debug(fp);
    } else if (sscanf(request, " v %30s %c", &verbosity[0], &d) == 1) {
        if (verbosity_int(verbosity)) {
            gstate.log_verbosity = verbosity_int(verbosity);
        } else {
            fprintf(fp, "Invalid verbosity\n");
        }
    } else if (sscanf(request, " v%c", &d) == 1) {
        gstate.log_verbosity = (gstate.log_verbosity + 1) % 3;
        fprintf(fp, "%s enabled\n", verbosity_str(gstate.log_verbosity));
    } else if (sscanf(request, " p%c", &d) == 1) {
        fprintf(fp, "  process id: %u\n", (unsigned) getpid());
        fprintf(fp, "  verbosity: %s\n", verbosity_str(gstate.log_verbosity));
        fprintf(fp, "  tun device: %s\n", gstate.tun_name);
        //debug_ip_addresses(fp, gstate.tun_name);
        if (gstate.protocol->console) {
            gstate.protocol->console(fp, "i\n");
        }
    } else if (gstate.protocol->console) {
        if (0 != gstate.protocol->console(fp, request)) {
            print_help(fp);
        }
    } else {
        fprintf(fp, "unknown/incomplete command\n");
        print_help(fp);
    }

    return ret;
}

void console_client_handler(int rc, int fd)
{
    char request[256];
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

        if (read_len == -1) {
            break;
        }

        ret = console_exec(fp, request);
    }

    fclose(fp);

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
