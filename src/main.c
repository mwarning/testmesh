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
//#include "traffic.h"
#include "interfaces.h"
#include "console.h"
#include "client.h"

#include "dsr-bloom-0/routing.h"
#include "counting-bloom-0/routing.h"
#include "flood-0/routing.h"
#include "flood-1/routing.h"
#include "vivaldi-0/routing.h"

#define MULTICAST_ADDR "ff12::114"
#define MULTICAST_PORT 4321

#define UNICAST_PORT 654

struct state gstate = {
    .protocol = NULL,
    .time_now = 0,
    .time_started = 0,
    .sock_help = -1,
    .sock_udp = -1,
    .sock_mcast_receive = -1,
    .sock_console = -1,
    .is_running = 1,
    .mcast_addr = {0},
    .ucast_addr = {0},
    .tun_name = "tun0",
    .tun_addr = {0},
    .tun_fd = 0,
    .log_to_syslog = 0,
    .log_to_terminal = 1, // disabled when running as daemon
    .log_to_socket = 1, // output log via domain socket
    .log_timestamp = 1, // log with timestamp
    .log_verbosity = VERBOSITY_DEBUG,
};

// list of all supported protocols
static const Protocol *g_protocols[32];
static int g_protocols_len = 0;

void register_protocol(const Protocol *p)
{
    g_protocols[g_protocols_len++] = p;
}

void send_ucast(const struct sockaddr_storage *addr, const void *data, int data_len)
{
    socklen_t slen = sizeof(struct sockaddr_storage);
    if (sendto(gstate.sock_udp, data, data_len, 0, (struct sockaddr*) addr, slen) == -1) {
        log_error("Failed send packet to %s: %s", str_addr(addr), strerror(errno));
    }
}

void setup_mcast_socket_receive(int *sock)
{
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("socket() %s", strerror(errno));
        exit(1);
    }

    int loop = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0) {
        log_error("setsockopt(IPV6_MULTICAST_LOOP) %s", strerror(errno));
        exit(1);
    }

    int on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
        printf("setsockopt IPV6_RECVPKTINFO ");
        exit(1);
    }

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*) &reuse, sizeof(reuse)) < 0) {
        log_error("setsockopt(SO_REUSEADDR): %s", strerror(errno));
        exit(1);
    }

    struct sockaddr_in6 any_addr = {
        .sin6_family = AF_INET6,
        .sin6_port = gstate.mcast_addr.sin6_port,
        .sin6_addr = in6addr_any,
        /*
        .sin6_addr = {0},
        .sin6_flowinfo = 0,
        .sin6_scope_id = 0,
        */
    };

    //gstate.mcast_addr.sin6_scope_id = ifindex;
    if (bind(fd, (struct sockaddr*) &any_addr, sizeof(any_addr)) < 0) {
        log_error("bind() to multicast address: %s", strerror(errno));
        exit(1);
    }

    struct ipv6_mreq group = {0};
    //group.ipv6mr_multiaddr = get_ip_addr(fd, interface->ifname);
    //group.ipv6mr_interface = if_nametoindex(gstate.tun_name); //hm, works
    memcpy(&group.ipv6mr_multiaddr, &gstate.mcast_addr.sin6_addr, sizeof(struct in6_addr));

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
        log_error("setsockopt(IPV6_ADD_MEMBERSHIP) %s", strerror(errno));
        exit(1);
    }

    *sock = fd;
}

void setup_unicast_socket(int *sock)
{
    int fd;

    if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        log_error("socket() %s", strerror(errno));
        exit(1);
    }

    int loop = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0) {
        log_error("setsockopt(IPV6_MULTICAST_LOOP) %s", strerror(errno));
        exit(1);
    }

    int on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
        printf("setsockopt IPV6_RECVPKTINFO ");
        exit(1);
    }

    // bind socket to port (works for IPv4 and IPv6)
    if (bind(fd, (struct sockaddr*) &gstate.ucast_addr, sizeof(gstate.ucast_addr)) == -1) {
        log_error("bind() to unicast address: %s", strerror(errno));
        exit(1);
    }

    *sock = fd;
}

void usage(const char *pname)
{
    fprintf(stderr,
        "Usage:  %s -i eth0 -i wlan0\n"
        "\n"
        "  -a              Routing algorithm.\n"
        "  -d              Run as daemon.\n"
        "  -i <interface>  Limit to given interfaces.\n"
        "  -p <peer>       Add a peer manually by address.\n"
        "  -s <path>       Domain socket to control the instance.\n"
        "  -d              Set route device (Default: tun0).\n"
        "  -h              Prints this help text.\n",
        pname
    );
}

const char *verbosity_str(int verbosity)
{
    switch (verbosity) {
        case VERBOSITY_DEBUG: return "DEBUG";
        case VERBOSITY_QUIET: return "QUIET";
        case VERBOSITY_VERBOSE: return "VERBOSE";
        default: return "UNKNOWN";
    }
}

// program name ends with -ctl
int is_client(const char *cmd)
{
    const char *sep = strrchr(cmd, '-');
    return sep && (strcmp(sep + 1, "ctl") == 0);
}

const Protocol *find_protocol(const char *protocol)
{
    for (int i = 0; i < g_protocols_len; i += 1) {
        if (0 == strcmp(g_protocols[i]->name, protocol)) {
            return g_protocols[i];
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    gstate.time_started = time(0);

    if (is_client(argv[0])) {
        // called as control client
        return client_main(argc, argv);
    }

    const char *control_socket_path = NULL;
    int do_fork = 0;
    int rc = 0;

    dsr_bloom_0_register();
    counting_bloom_0_register();
    flood_0_register();
    flood_1_register();
    vivaldi_0_register();

    if (g_protocols_len == 0) {
        log_error("No routing protocol available.");
        return EXIT_FAILURE;
    }

    // set to only protocol
    if (g_protocols_len == 1) {
        gstate.protocol = g_protocols[0];
    }

    int option;
    while ((option = getopt(argc, argv, "di:a:p:s:t:h")) > 0) {
        switch(option) {
            case 'a':
                gstate.protocol = find_protocol(optarg);
                if (!gstate.protocol) {
                    log_error("Protocol not found: %s", optarg);
                    return EXIT_FAILURE;
                }
                break;
            case 'd':
                do_fork = 1;
                break;
            case 'i':
                if (gstate.protocol == NULL) {
                    log_error("Please set protocol first!");
                    return EXIT_FAILURE;
                }
                add_interface(optarg);
                break;
            case 'p':
                if (gstate.protocol == NULL) {
                    log_error("Please set protocol first!");
                    return EXIT_FAILURE;
                }
                if (gstate.protocol->add_peer == NULL) {
                    log_error("Protocol %s does not support peers!", gstate.protocol->name);
                    return EXIT_FAILURE;
                }
                rc = gstate.protocol->add_peer(stdout, optarg);
                break;
            case 's':
                control_socket_path = optarg;
                break;
            case 't':
                gstate.tun_name = strdup(optarg);
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                log_error("Unknown option %c", option);
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (rc != 0) {
        return EXIT_FAILURE;
    }

    if (argc > optind) {
        log_error("Too many options!");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (getuid() != 0) {
        printf("Must run as root: %s\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (gstate.protocol == NULL) {
        fprintf(stderr, "No protocol selected (-a):\n");
        for (int i = 0; i < g_protocols_len; i += 1) {
            fprintf(stderr, "%s\n", g_protocols[i]->name);
        }
        return EXIT_FAILURE;
    }

    gstate.sock_help = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (gstate.sock_help < 0) {
        log_error("socket() %s", strerror(errno));
        return EXIT_FAILURE;
    }

    // setup multicast address
    gstate.mcast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, MULTICAST_ADDR, &gstate.mcast_addr.sin6_addr);
    gstate.mcast_addr.sin6_port = htons(MULTICAST_PORT);

    // setup unicast address for bind
    gstate.ucast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::", &gstate.ucast_addr.sin6_addr);
    gstate.ucast_addr.sin6_port = htons(UNICAST_PORT);

    unix_signals();

    if ((gstate.tun_fd = tun_alloc(gstate.tun_name)) < 0) {
        log_error("Error creating to %s interface: %s", gstate.tun_name, strerror(errno));
        return EXIT_FAILURE;
    }

    if (interface_set_up(gstate.sock_help, gstate.tun_name) < 0) {
        log_error("Failed to set interface %S up: %s", gstate.tun_name, strerror(errno));
        return EXIT_FAILURE;
    }

    if (interface_get_addr6(&gstate.tun_addr, gstate.tun_name) < 0) {
        log_error("Failed to get IPv6 address of interface: %s", gstate.tun_name);
        return EXIT_FAILURE;
    }

    gstate.protocol->init();

    log_info("Protocol: %s", gstate.protocol->name);
    log_info("Entry device: %s", gstate.tun_name);
    log_info("Verbosity: %s", verbosity_str(gstate.log_verbosity));
    log_info("Listen on multicast: %s", str_addr6(&gstate.mcast_addr));
    log_info("Listen on unicast: %s", str_addr6(&gstate.ucast_addr));
    log_info("Address of %s: %s", gstate.tun_name, str_in6(&gstate.tun_addr));

    if (control_socket_path) {
        log_info("Control socket: %s", control_socket_path);
    }

    setup_unicast_socket(&gstate.sock_udp); // send to various devices
    setup_mcast_socket_receive(&gstate.sock_mcast_receive);

    net_add_handler(gstate.sock_udp, gstate.protocol->ext_handler);
    net_add_handler(gstate.sock_mcast_receive, gstate.protocol->ext_handler);

    //net_add_handler(-1, &periodic_handler);
    net_add_handler(gstate.tun_fd, gstate.protocol->tun_handler);

    interfaces_init();

    if (control_socket_path) {
        unix_create_unix_socket(control_socket_path, &gstate.sock_console);
        net_add_handler(gstate.sock_console, &console_server_handler);
    }

    if (do_fork) {
        if (chdir("/") != 0) {
            log_error("Changing working directory to '/' failed: %s", strerror(errno));
            exit(1);
        }

        // force syslog
        gstate.log_to_syslog = 1;
        gstate.log_to_terminal = 0;

        // Close pipes
        fclose(stderr);
        fclose(stdout);
        fclose(stdin);

        unix_fork();
    } else {
        printf("Press Enter for help.\n");
        net_add_handler(STDIN_FILENO, &console_client_handler);
    }

    net_loop();

    log_info("Shutting down...");

    if (control_socket_path) {
        unix_remove_unix_socket(control_socket_path, gstate.sock_console);
    }

    return EXIT_SUCCESS;
}
