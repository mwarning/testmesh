#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "main.h"
#include "utils.h"
#include "interfaces.h"
#include "log.h"


enum OPCODE {
    oProtocol,
    oInterface,
    oFindInterfaces,
    oGatewayIdentifier,
    oOwnIdentifier,
    oDaemon,
    oLogLevel,
    oEtherType,
    oControlSocket,
    oTunName,
    oTunSetup,
    oDisableStdin,
    oLogFile,
    oLogTime,
    oEnableIPv4,
    oEnableIPv6,
    oPeer,
    oHelp,
    oVersion
};

struct option_t {
    const char *name;
    uint16_t num_args;
    uint16_t code;
};

static struct option_t g_options[] = {
    {"--protocol", 1, oProtocol},
    {"-p", 1, oProtocol},
    {"--gateway-id", 1, oGatewayIdentifier},
    {"--own-id", 1, oOwnIdentifier},
    {"--ifname", 1, oInterface},
    {"--find-interfaces", 0, oFindInterfaces},
    {"--interface", 1, oInterface},
    {"-i", 1, oInterface},
    {"--log-file", 1, oLogFile},
    {"-lf", 1, oLogFile},
    {"--ether-type", 1, oEtherType},
    {"--peer", 1, oPeer},
    {"--tun-name", 1, oTunName},
    {"--tun-setup", 0, oTunSetup},
    {"--disable-stdin", 0, oDisableStdin},
    {"--control", 1, oControlSocket},
    {"-c", 1, oControlSocket},
    {"--log-level", 1, oLogLevel},
    {"-ll", 1, oLogLevel},
    {"--log-time", 0, oLogTime},
    {"-lt", 0, oLogTime},
    {"--enable-ipv4", 1, oEnableIPv4},
    {"-4", 1, oEnableIPv4},
    {"--enable-ipv6", 1, oEnableIPv6},
    {"-6", 1, oEnableIPv6},
    {"--daemon", 0, oDaemon},
    {"-d", 0, oDaemon},
    {"--help", 0, oHelp},
    {"-h", 0, oHelp},
    {"--version", 0, oVersion},
    {"-v", 0, oVersion},
    {NULL, 0, 0}
};

static const char *usage_str = 
    "Usage: testmesh -i eth0 -i wlan0\n"
    "\n"
    "  --protocol,-p <protocol>    Select routing protocol\n"
    "  --daemon,-d                 Run as daemon\n"
    "  --interface,-i <interface>  Limit to given interfaces\n"
    "  --find-interfaces           Find and add interfaces automatically\n"
    "  --own-id <id>               Identifier of this node (default: <random>)\n"
    "  --gateway-id <id>           Identifier of the gateway node (default: <none>)\n"
    "  --peer <address>            Add a peer manually by address\n"
    "  --control,-c <path>         Control socket to connect to a daemon\n"
    "  --tun-name <ifname>         Network entry interface, use none to disable (Default: tun0)\n"
    "  --tun-setup <1/0>           Auto configure entrey interface with IP address (Default: 1)\n"
    "  --ether-type <hex>          Ethernet type (Default: 88B5)\n"
    "  --log-file,-lf <path>       Write log output to file\n"
    "  --log-level,-ll <level>     Log level. From 0 to " STR(MAX_LOG_LEVEL) " (Default: 3)\n"
    "  --log-timestamp,-lt         Add timestamps to log output\n"
    "  --disable-stdin             Disable interactive console on startup\n"
    "  --enable-ipv4,-4 <0/1>      Enable IPv4 (Default: 0)\n"
    "  --enable-ipv6,-6 <1/0>      Enable IPv6 (Default: 1)\n"
    "  --help,-h                   Prints this help text\n"
    "  --version                   Print version";

static int parse_hex(uint64_t *ret, const char *val, int bytes)
{
    int len = strlen(val);
    if (len < 3 || len > (2 + 2 * bytes) || (len % 2) || val[0] != '0' || val[1] != 'x') {
       return 1;
    }

    char *end = NULL;
    *ret = strtoul(val + 2, &end, 16);
    return (val + len) != end;
}

static const struct option_t *find_option(const char *name)
{
    struct option_t *option;

    option = g_options;
    while (option->name) {
        if (0 == strcmp(name, option->name)) {
            return option;
        }
        option++;
    }

    return NULL;
}

static int conf_set(const char *opt, const char *val)
{
    const struct option_t *option;
    uint64_t n;

    option = find_option(opt);

    if (option == NULL) {
        log_error("Unknown parameter: %s", opt);
        return EXIT_FAILURE;
    }

    if (option->num_args == 1 && val == NULL) {
        log_error("Argument expected for option: %s", opt);
        return EXIT_FAILURE;
    }

    if (option->num_args == 0 && val != NULL) {
        log_error("No argument expected for option: %s", opt);
        return EXIT_FAILURE;
    }

    switch (option->code)
    {
    case oHelp:
        printf("%s\n\n", usage_str);
        protocols_print(stdout);
        exit(0);
    case oVersion:
        printf(GEOMESH_VERSION "\n");
        exit(0);
    case oProtocol:
        gstate.protocol = protocols_find(val);
        if (gstate.protocol == NULL) {
            log_error("Unknown protocol: %s", val);
            return EXIT_FAILURE;
        }
        break;
    case oDaemon:
        gstate.do_fork = 1;
        break;
    case oFindInterfaces:
        gstate.find_interfaces = 1;
        break;
    case oInterface:
        if (gstate.protocol == NULL) {
            log_error("Please set protocol first!");
            return EXIT_FAILURE;
        }
        interface_add(val);
        break;
    case oLogFile:
        gstate.log_to_file = fopen(val, "w");
        if (gstate.log_to_file == NULL) {
            log_error("Failed to open file to log: %s (%s)", val, strerror(errno));
            return EXIT_FAILURE;
        }
        break;
    case oLogTime:
        gstate.log_time = 1;
        break;
    case oTunName:
        if (0 == strcmp(val, "none")) {
            gstate.tun_name = NULL;
        } else {
            gstate.tun_name = strdup(val);
        }
        break;
    case oTunSetup:
        gstate.tun_setup = 1;
        break;
    case oControlSocket:
        gstate.control_socket_path = strdup(val);
        break;
    case oGatewayIdentifier:
        if (parse_hex(&n, val, sizeof(gstate.gateway_id))) {
            log_error("Invalid hex value for %s: %s", opt, val);
            return EXIT_FAILURE;
        }
        if (gstate.own_id_set && gstate.own_id == n) {
            log_error("Own and gateway id are the same: %08x", n);
            return EXIT_FAILURE;
        }
        gstate.gateway_id = n;
        gstate.gateway_id_set = 1;
        break;
    case oOwnIdentifier:
        if (parse_hex(&n, val, sizeof(gstate.own_id))) {
            log_error("Invalid hex value for %s: %s", opt, val);
            return EXIT_FAILURE;
        }
        if (gstate.gateway_id_set && gstate.gateway_id == n) {
            log_error("Gateway and own id are the same: %08x", n);
            return EXIT_FAILURE;
        }
        gstate.own_id = n;
        gstate.own_id_set = 1;
        break;
    case oDisableStdin:
        gstate.disable_stdin = 1;
        break;
    case oEnableIPv4:
        gstate.enable_ipv4 = n;
        break;
    case oEnableIPv6:
        gstate.enable_ipv6 = n;
        break;
    case oEtherType:
        if (parse_hex(&n, val, sizeof(gstate.ether_type)) || n == 0) {
            log_error("Invalid hex value for %s: %s", opt, val);
            return EXIT_FAILURE;
        }
        gstate.ether_type = n;
        break;
    case oLogLevel: {
        char *ptr = NULL;
        const char *end = val + strlen(val);
        uint32_t log_level = strtoul(val, &ptr, 10);
        if (ptr != end || log_level > MAX_LOG_LEVEL) {
            log_error("Invalid log level: %s", val);
            return EXIT_FAILURE;
        }
        gstate.log_level = log_level;
        break;
    }
    default:
        log_error("Unhandled option: %s", opt);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int conf_setup(int argc, char **argv)
{
    const char *opt;
    const char *val;
    int rc;
    int i;

    for (i = 1; i < argc; ++i) {
        opt = argv[i];
        val = argv[i + 1];

        if (val && val[0] != '-') {
            // -x abc
            rc = conf_set(opt, val);
            i += 1;
        } else {
            // -x
            rc = conf_set(opt, NULL);
        }

        if (rc == EXIT_FAILURE) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
