#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> // getuid(), chdir(), STDIN_FILENO
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // IFF_TUN, IFF_NO_PI, TUNSETIFF
#include <stddef.h>
#include <stdarg.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "unix.h"
#include "tun.h"
//#include "traffic.h"
#include "interfaces.h"
#include "console.h"
#include "client.h"
#include "protocols.h"


struct state gstate = {
    .af = AF_UNSPEC,
    .protocol = DEFAULT_PROTOCOL,
    .do_fork = false,
    .time_now = 0,
    .time_started = 0,
    .sock_help = -1,
    .sock_udp = -1,
#ifdef MULTICAST
    .sock_mcast_receive = -1,
#endif
    .sock_console = -1,
    .ether_type = 0x88b5, // "Local Experiment Ethertype 1"
    .find_interfaces = FIND_INTERFACES_OFF,

    .gateway_id = 0,
    .gateway_id_set = false,
    .own_id = 0,
    .own_id_set = false,

    .is_running = 1,
    .control_socket_path = NULL,
    .disable_stdin = false,
#ifdef MULTICAST
    .mcast_addr = {0},
#endif
    .ucast_addr = {0},

    .enable_ipv4 = false,
    .enable_ipv6 = true,

    .tun_name = "tun0",
    .tun_fd = -1,

    .tun_setup = 1, // auto configure IP address/route
    .tun_setup_ipv4_mtu = 1400, // only used if tun IPv4 setup is enabled

    .log_to_syslog = false,
    .log_to_file = NULL,
    .log_to_terminal = true, // disabled when running as daemon
    .log_to_socket = true, // output log via domain socket
    .log_time = false, // log with timestamp
    .log_level = 3,
};

// list of all supported protocols
static const Protocol *g_protocols[32];
static int g_protocols_len = 0;


void protocols_print(FILE *fd)
{
    fprintf(fd, "Valid protocols: ");
    for (size_t i = 0; i < g_protocols_len; i += 1) {
        fprintf(fd, (i ? ", %s" : "%s"), g_protocols[i]->name);
    }
    fprintf(fd, "\n");
}

const Protocol *protocols_find(const char *protocol)
{
    for (size_t i = 0; i < g_protocols_len; i += 1) {
        if (0 == strcmp(g_protocols[i]->name, protocol)) {
            return g_protocols[i];
        }
    }

    return NULL;
}

void protocols_register(const Protocol *p)
{
    if (g_protocols_len >= ARRAY_SIZE(g_protocols)) {
        log_error("Too many protocols.");
        exit(1);
    }

    if (p->name == NULL) {
        log_error("Protocol with missing name.");
        exit(1);
    }

    if (protocols_find(p->name)) {
        log_error("Duplicate protocol: %s", p->name);
        exit(1);
    }

    g_protocols[g_protocols_len++] = p;
}

#ifdef MULTICAST
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
        printf("setsockopt(IPV6_RECVPKTINFO)");
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
#endif

static int create_udp_socket(const struct sockaddr_in6 *addr)
{
    int fd;

    if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        log_error("socket() %s", strerror(errno));
        return -1;
    }

    int loop = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) == -1) {
        log_error("setsockopt(IPV6_MULTICAST_LOOP) %s", strerror(errno));
        return -1;
    }
/*
    int on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == -1) {
        printf("setsockopt IPV6_RECVPKTINFO ");
        return -1;
    }
*/
    // bind socket to port (works for IPv4 and IPv6)
    if (bind(fd, (struct sockaddr*) addr, sizeof(struct sockaddr_in6)) == -1) {
        log_error("bind() to unicast address: %s", strerror(errno));
        return -1;
    }

    return fd;
}

// program name matches *-ctl
static bool is_client(const char *cmd)
{
    const char *sep = strrchr(cmd, '-');
    return sep && (strcmp(sep + 1, "ctl") == 0);
}

int main(int argc, char *argv[])
{
    uint64_t now = time_millis_now();
    gstate.time_started = now;
    gstate.time_now = now;

    if (argc > 0 && is_client(argv[0])) {
        // called as control client
        return client_main(argc, argv);
    }

    register_all_protocols();

    if (!conf_setup(argc, argv)) {
        return EXIT_FAILURE;
    }

    if (!gstate.own_id_set) {
        // not set by configuration setting
        if (bytes_random(&gstate.own_id, sizeof(gstate.own_id)) != sizeof(gstate.own_id)) {
            log_error("Cannot create random identifier.");
            return EXIT_FAILURE;
        }
        gstate.own_id_set = true;
    }

    if (g_protocols_len == 0) {
        log_error("No routing protocol available.");
        return EXIT_FAILURE;
    }

    // set to the only protocol
    if (g_protocols_len == 1) {
        gstate.protocol = g_protocols[0];
    }

    if (gstate.protocol == NULL) {
        log_error("No protocol selected (-p)\n");
        protocols_print(stderr);
        return EXIT_FAILURE;
    }

    if (getuid() != 0) {
        log_error("Must run as root.\n");
        return EXIT_FAILURE;
    }

    log_info("Protocol:       %s", gstate.protocol->name);

    if (gstate.own_id_set) {
        log_info("Own ID:         0x%08x", gstate.own_id);
    }

    if (gstate.gateway_id_set) {
        log_info("Gateway ID:     0x%08x", gstate.gateway_id);
    }

    if (gstate.tun_name) {
        log_info("Tunnel Device:  %s", gstate.tun_name);
    }

    {
        // print current time
        time_t rawtime;
        char time_buf[32];
        time(&rawtime);
        strftime(time_buf, 26, "%Y:%m:%d %H:%M:%S", localtime(&rawtime));
        log_info("Started:        %s", time_buf);
    }

    gstate.time_resolution = time_millis_resolution();
    log_info("Time:           +/- %zums", (size_t) gstate.time_resolution);

    log_info("Log Level:      %s", log_level_str(gstate.log_level));
    log_info("IPv4/IPv6:      %s/%s", str_onoff(gstate.enable_ipv4), str_onoff(gstate.enable_ipv6));

    if (gstate.config_path) {
        log_info("Config File:    %s", gstate.config_path);
    }

    {
        // initialize random number generator for future rand() calls
        unsigned init = 0;
        if (bytes_random(&init, sizeof(init)) != sizeof(init)) {
            log_error("Failed to initialize random number generator");
            return EXIT_FAILURE;
        } else {
            log_verbose("Init RND:       srand(%u)", init);
            srand(init);
        }
    }

    gstate.sock_help = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (gstate.sock_help < 0) {
        log_error("socket() %s", strerror(errno));
        return EXIT_FAILURE;
    }

#ifdef MULTICAST
    // setup multicast address
    gstate.mcast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, MULTICAST_ADDR, &gstate.mcast_addr.sin6_addr);
    gstate.mcast_addr.sin6_port = htons(MULTICAST_PORT);
#endif

    // setup unicast address for bind
    gstate.ucast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::", &gstate.ucast_addr.sin6_addr);
    gstate.ucast_addr.sin6_port = htons(UNICAST_UDP_PORT);

    unix_signals();

    if (gstate.tun_name) {
        if (tun_init(gstate.own_id, gstate.tun_name) != EXIT_SUCCESS) {
            return EXIT_FAILURE;
        }
    }

    if (gstate.control_socket_path) {
        log_info("Control socket: %s", gstate.control_socket_path);
    }

    if (gstate.protocol->ext_handler_l2) {
        log_info("Ether-type:     0x%04x", gstate.ether_type);
    }

    if (gstate.protocol->init_handler) {
        gstate.protocol->init_handler();
    }

    if (gstate.protocol->ext_handler_l3) {
        gstate.sock_udp = create_udp_socket(&gstate.ucast_addr);
        if (gstate.sock_udp == -1) {
            return EXIT_FAILURE;
        }
#ifdef MULTICAST
        setup_mcast_socket_receive(&gstate.sock_mcast_receive);
        log_info("Listen:         %s (multicast)", str_addr6(&gstate.mcast_addr));
#endif
        log_info("Listen:         %s", str_addr6(&gstate.ucast_addr));
    }

    if (!interfaces_init()) {
        return EXIT_FAILURE;
    }

    if (!console_setup()) {
        return EXIT_FAILURE;
    }

    if (gstate.do_fork) {
        if (chdir("/") != 0) {
            log_error("chdir(\"/\"): %s", strerror(errno));
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
        if (!gstate.disable_stdin) {
            printf("Press Enter for help.\n\n");
            net_add_handler(STDIN_FILENO, &console_client_handler);
        }
    }

    net_loop();

    log_info("Shutting down...");

    if (gstate.protocol->exit_handler) {
        gstate.protocol->exit_handler();
    }

    if (gstate.log_to_file) {
        fclose(gstate.log_to_file);
    }

    console_free();

    return EXIT_SUCCESS;
}
