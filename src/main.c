#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // IFF_TUN, IFF_NO_PI, TUNSETIFF
#include <linux/if_tun.h>
#include <fcntl.h> // open()
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "unix.h"
//#include "traffic.h"
#include "interfaces.h"
#include "console.h"
#include "client.h"
#include "protocols.h"

struct state gstate = {
    .protocol = NULL,
    .do_fork = 0,
    .time_now = 0,
    .time_started = 0,
    .sock_help = -1,
    .sock_udp = -1,
    .sock_mcast_receive = -1,
    .sock_console = -1,
    .ether_type = 0x88b5, // Local Experiment Ethertype 1

    .gateway_id = 0,
    .own_id = 0,

    .is_running = 1,
    .control_socket_path = NULL,
    .disable_stdin = 0,
    .mcast_addr = {0},
    .ucast_addr = {0},

    .tun_name = "tun0",
    .tun_fd = 0,

    .log_to_syslog = 0,
    .log_to_file = NULL,
    .log_to_terminal = 1, // disabled when running as daemon
    .log_to_socket = 1, // output log via domain socket
    .log_timestamp = 1, // log with timestamp
    .log_verbosity = VERBOSITY_DEBUG,
};

// list of all supported protocols
static const Protocol *g_protocols[32];
static int g_protocols_len = 0;


const Protocol *find_protocol(const char *protocol)
{
    for (int i = 0; i < g_protocols_len; i += 1) {
        if (0 == strcmp(g_protocols[i]->name, protocol)) {
            return g_protocols[i];
        }
    }

    return NULL;
}

void register_protocol(const Protocol *p)
{
    if (find_protocol(p->name)) {
        log_error("Duplicate protocol: %s", p->name);
        exit(1);
    }

    g_protocols[g_protocols_len++] = p;
}

static void setup_mcast_socket_receive(int *sock)
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

static void setup_unicast_socket(int *sock)
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

static int tun_alloc(const char *dev)
{
    const char *clonedev = "/dev/net/tun";
    struct ifreq ifr = {0};
    int fd;

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        log_error("open %s: %s", clonedev, strerror(errno));
        return -1;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strcpy(ifr.ifr_name, dev);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        log_error("ioctl(TUNSETIFF) %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (0 != strcmp(ifr.ifr_name, dev)) {
        return -1;
    }

    return fd;
}

// program name matches *-ctl
static int is_client(const char *cmd)
{
    const char *sep = strrchr(cmd, '-');
    return sep && (strcmp(sep + 1, "ctl") == 0);
}

static int setup_tun0(uint32_t id, const char *ifname)
{
    char cmd[128];
    int rc;
    uint16_t *addr = (uint16_t*) &id;

    sprintf(cmd, "ip link set up %s", ifname);
    rc = system(cmd);
    if (rc != 0) {
        log_error("Failed to execute: %s", cmd);
        return 1;
    }

    sprintf(cmd, "ip -4 addr flush dev %s", ifname);
    rc = system(cmd);
    if (rc != 0) {
        log_error("Failed to execute: %s", cmd);
        return 1;
    }

    sprintf(cmd, "ip -6 addr flush dev %s", ifname);
    rc = system(cmd);
    if (rc != 0) {
        log_error("Failed to execute: %s", cmd);
        return 1;
    }

    sprintf(cmd, "ip a a fe80::%04x:%04x/64 dev tun0", addr[1], addr[0]);
    rc = system(cmd);
    if (rc != 0) {
        log_error("Failed to execute: %s", cmd);
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    gstate.time_started = time(0);

    if (is_client(argv[0])) {
        // called as control client
        return client_main(argc, argv);
    }

    srand(gstate.time_started);

    register_all_protocols();

    if (conf_setup(argc, argv) == EXIT_FAILURE) {
        return EXIT_FAILURE;
    }

    if (gstate.own_id == 0) {
        if (!bytes_random(&gstate.own_id, sizeof(gstate.own_id))) {
            log_error("Cannot create random identifier.");
            return EXIT_FAILURE;
        }
    }

    if (g_protocols_len == 0) {
        log_error("No routing protocol available.");
        return EXIT_FAILURE;
    }

    // set to only protocol
    if (g_protocols_len == 1) {
        gstate.protocol = g_protocols[0];
    }

    if (getuid() != 0) {
        printf("Must run as root: %s\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (gstate.protocol == NULL) {
        fprintf(stderr, "No protocol selected (-p):\n");
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

    log_info("Own ID: 0x%04x", gstate.own_id);

    if (setup_tun0(gstate.own_id, gstate.tun_name)) {
        log_error("Failed to set up tunnel interface.");
        return EXIT_FAILURE;
    }

    if (gstate.gateway_id) {
        log_info("Gateway ID: 0x%04x", gstate.gateway_id);
    } else {
        log_info("Gateway ID: none");
    }

    if (gstate.protocol->init) {
        gstate.protocol->init();
    }

    log_info("Protocol: %s", gstate.protocol->name);
    log_info("Entry Device: %s", gstate.tun_name);
    log_info("Verbosity: %s", verbosity_str(gstate.log_verbosity));

    if (gstate.control_socket_path) {
        log_info("Control socket: %s", gstate.control_socket_path);
    }

    if (gstate.protocol->ext_handler_l2) {
        log_info("Ether-type: 0x%04x", gstate.ether_type);
    }

    if (gstate.protocol->ext_handler_l3) {
        setup_unicast_socket(&gstate.sock_udp);
        setup_mcast_socket_receive(&gstate.sock_mcast_receive);

        net_add_handler(gstate.sock_udp, gstate.protocol->ext_handler_l3);
        net_add_handler(gstate.sock_mcast_receive, gstate.protocol->ext_handler_l3);

        log_info("Listen on multicast: %s", str_addr6(&gstate.mcast_addr));
        log_info("Listen on unicast: %s", str_addr6(&gstate.ucast_addr));
    }

    if (gstate.protocol->tun_handler) {
        net_add_handler(gstate.tun_fd, gstate.protocol->tun_handler);
    }

    interfaces_init();

    if (gstate.control_socket_path) {
        unix_create_unix_socket(gstate.control_socket_path, &gstate.sock_console);
        net_add_handler(gstate.sock_console, &console_server_handler);
    }

    if (gstate.do_fork) {
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
        if (gstate.disable_stdin == 0) {
            printf("Press Enter for help.\n");
            net_add_handler(STDIN_FILENO, &console_client_handler);
        }
    }

    net_loop();

    log_info("Shutting down...");

    if (gstate.log_to_file) {
        fclose(gstate.log_to_file);
    }

    if (gstate.control_socket_path) {
        unix_remove_unix_socket(gstate.control_socket_path, gstate.sock_console);
    }

    return EXIT_SUCCESS;
}
