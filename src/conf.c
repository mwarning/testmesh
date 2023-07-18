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
    {"--find-interfaces", 1, oFindInterfaces},
    {"--interface", 1, oInterface},
    {"-i", 1, oInterface},
    {"--log-file", 1, oLogFile},
    {"-lf", 1, oLogFile},
    {"--ether-type", 1, oEtherType},
    {"--peer", 1, oPeer},
    {"--tun-name", 1, oTunName},
    {"--tun-setup", 1, oTunSetup},
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
    "  --protocol,-p <protocol>        Select routing protocol\n"
    "  --daemon,-d                     Run as daemon in background\n"
    "  --interface,-i <interface>      Limit to given interfaces\n"
    "  --find-interfaces [on/off/auto] Find and add interfaces automatically (default: off)\n"
    "  --own-id <id>                   Identifier of this node (default: <random>)\n"
    "  --gateway-id <id>               Identifier of the gateway node (default: <none>)\n"
    "  --peer <address>                Add a peer manually by address\n"
    "  --control,-c <path>             Control socket to connect to a daemon\n"
    "  --tun-name <ifname>             Network entry interface, use none to disable (default: tun0)\n"
    "  --tun-setup <on/off>            Auto configure entry interface with IP address (default: on)\n"
    "  --ether-type <hex>              Ethernet type for layer-2 packets (default: 88B5)\n"
    "  --log-file,-lf <path>           Write log output to file\n"
    "  --log-level,-ll <level>         Logging level. From 0 to " STR(MAX_LOG_LEVEL) " (default: 3)\n"
    "  --log-time,-lt                  Add timestamps to logging output\n"
    "  --disable-stdin                 Disable interactive console on startup\n"
    "  --enable-ipv4,-4 <on/off>       Enable IPv4 (default: off)\n"
    "  --enable-ipv6,-6 <on/off>       Enable IPv6 (default: on)\n"
    "  --help,-h                       Print this help text\n"
    "  --version                       Print version";

static int parse_hex(uint64_t *ret, const char *val, int bytes)
{
    int len = strlen(val);
    if (len < 3 || len > (2 + 2 * bytes) || (len % 2) != 0 || val[0] != '0' || val[1] != 'x') {
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

    switch (option->code) {
    case oHelp:
        printf("%s\n\n", usage_str);
        protocols_print(stdout);
        exit(0);
    case oVersion:
        printf(PROGRAM_NAME " " PROGRAM_VERSION "\n");
        exit(0);
    case oPeer:
        if (gstate.protocol == NULL) {
            log_error("%s needs to be used after a protocol", option->name);
            return EXIT_FAILURE;
        }
        if (gstate.protocol->peer_handler == NULL) {
            log_error("Protocol %s does not support peers", gstate.protocol->name);
            return EXIT_FAILURE;
        }
        if (!gstate.protocol->peer_handler(val, true)) {
            log_error("Failed to add peer: %s", val);
            return EXIT_SUCCESS;
        }
        break;
    case oProtocol:
        gstate.protocol = protocols_find(val);
        if (gstate.protocol == NULL) {
            log_error("Unknown protocol: %s", val);
            return EXIT_FAILURE;
        }
        break;
    case oDaemon:
        gstate.do_fork = true;
        break;
    case oFindInterfaces:
        if (0 == strcmp(val, "on")) {
            gstate.find_interfaces = FIND_INTERFACES_ON;
        } else if (0 == strcmp(val, "off")) {
            gstate.find_interfaces = FIND_INTERFACES_OFF;
        } else if (0 == strcmp(val, "auto")) {
            gstate.find_interfaces = FIND_INTERFACES_AUTO;
        } else {
            log_error("Unknown value for %s %s", opt, val);
            return EXIT_FAILURE;
        }
        break;
    case oInterface:
        if (gstate.protocol == NULL) {
            log_error("%s needs to be used after a protocol", option->name);
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
        gstate.log_time = true;
        break;
    case oTunName:
        if (0 == strcmp(val, "none")) {
            gstate.tun_name = NULL;
        } else {
            gstate.tun_name = strdup(val);
        }
        break;
    case oTunSetup:
        if (0 == strcmp(val, "on")) {
            gstate.tun_setup = true;
        } else if (0 == strcmp(val, "off")) {
            gstate.tun_setup = false;
        } else {
            log_error("Unknown value for %s %s", opt, val);
            return EXIT_FAILURE;
        }
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
        gstate.gateway_id_set = true;
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
        gstate.own_id_set = true;
        break;
    case oDisableStdin:
        gstate.disable_stdin = true;
        break;
    case oEnableIPv4:
        if (0 == strcmp(val, "on")) {
            gstate.enable_ipv4 = true;
        } else if (0 == strcmp(val, "off")) {
            gstate.enable_ipv4 = false;
        } else {
            log_error("Unknown value for %s %s", opt, val);
            return EXIT_FAILURE;
        }
        break;
    case oEnableIPv6:
        if (0 == strcmp(val, "on")) {
            gstate.enable_ipv6 = true;
        } else if (0 == strcmp(val, "off")) {
            gstate.enable_ipv6 = false;
        } else {
            log_error("Unknown value for %s %s", opt, val);
            return EXIT_FAILURE;
        }
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
    size_t i;

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
