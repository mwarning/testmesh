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
    oGatewayIdentifier,
    oOwnIdentifier,
    oDaemon,
    oVerbosity,
    oEtherType,
    oControlSocket,
    oTunName,
    oTunSetup,
    oDisableStdin,
    oLogFile,
    oDisableIpv4,
    oDisableIpv6,
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
    {"-i", 1, oInterface},
    {"--log", 1, oLogFile},
    {"--ether-type", 1, oEtherType},
    {"--peer", 1, oPeer},
    {"--tun-name", 1, oTunName},
    {"--tun-setup", 0, oTunSetup},
    {"--disable-stdin", 0, oDisableStdin},
    {"--control", 1, oControlSocket},
    {"-c", 1, oControlSocket},
    {"--verbosity", 1, oVerbosity},
    {"--disable-ipv4", 0, oDisableIpv4},
    {"--disable-ipv6", 0, oDisableIpv6},
    {"--daemon", 0, oDaemon},
    {"-d", 0, oDaemon},
    {"--help", 0, oHelp},
    {"-h", 0, oHelp},
    {"-v", 1, oVersion},
    {"--version", 0, oVersion},
    {NULL, 0, 0}
};

static const char *usage_str = 
    "Usage: geomesh -i eth0 -i wlan0\n"
    "\n"
    "  --protocol,-p               Select routing protocol.\n"
    "  --daemon,-d                 Run as daemon.\n"
    "  --interface,-i <interface>  Limit to given interfaces.\n"
    "  --log <path>                Write log output to file.\n"
    "  --peer <address>            Add a peer manually by address.\n"
    "  --control,-c <path>         Control socket to connect to a daemon.\n"
    "  --tun-name <ifname>         Set route device (Default: tun0).\n"
    "  --tun-setup                 Setup tunnel interface with ip addresses and routes.\n"
    "  --ether-type <hex>          Ethernet type. (Default: 88b5)\n"
    "  --verbosity <level>         Set verbosity to quiet, verbose or debug (Default: verbose).\n"
    "  --disable-stdin             Disable interactive console on startup.\n"
    "  --disable-ipv4              Disable IPv4\n"
    "  --disable-ipv6              Disable IPv6\n"
    "  --help,-h                   Prints this help text.\n"
    "  --version,-v                Print version.";

static struct { const char *str; int i; } g_verbosity_map[] = {
    {"QUIET", VERBOSITY_QUIET},
    {"VERBOSE", VERBOSITY_VERBOSE},
    {"DEBUG", VERBOSITY_DEBUG},
};

const char *verbosity_str(int verbosity)
{
    for (int i = 0; i < ARRAY_NELEMS(g_verbosity_map); i++) {
        if (g_verbosity_map[i].i == verbosity) {
            return g_verbosity_map[i].str;
        }
    }
    return "UNKNOWN";
}

int verbosity_int(const char *verbosity)
{
    for (int i = 0; i < ARRAY_NELEMS(g_verbosity_map); i++) {
        if (0 == strcasecmp(g_verbosity_map[i].str, verbosity)) {
            return g_verbosity_map[i].i;
        }
    }
    return -1;
}

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
        printf("%s\n", usage_str);
        exit(0);
    case oVersion:
        printf("1.0.0\n");
        exit(0);
    case oProtocol:
        gstate.protocol = find_protocol(val);
        if (gstate.protocol == NULL) {
            log_error("Unknown protocol: %s", val);
            return EXIT_FAILURE;
        }
        break;
    case oDaemon:
        gstate.do_fork = 1;
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
    case oTunName:
        gstate.tun_name = strdup(val);
        break;
    case oTunSetup:
        gstate.tun_setup = 1;
        break;
    case oControlSocket:
        gstate.control_socket_path = strdup(val);
        break;
    case oGatewayIdentifier:
        if (parse_hex(&n, val, sizeof(gstate.gateway_id)) || n == 0) {
            log_error("Invalid hex value for %s: %s", opt, val);
            return EXIT_FAILURE;
        }
        if (gstate.own_id == n) {
            log_error("Own and gateway id are the same: %08x", n);
            return EXIT_FAILURE;
        }
        gstate.gateway_id = n;
        break;
    case oOwnIdentifier:
        if (parse_hex(&n, val, sizeof(gstate.own_id)) || n == 0) {
            log_error("Invalid hex value for %s: %s", opt, val);
            return EXIT_FAILURE;
        }
        if (gstate.gateway_id == n) {
            log_error("Gateway and own id are the same: %08x", n);
            return EXIT_FAILURE;
        }
        gstate.own_id = n;
        break;
    case oDisableStdin:
        gstate.disable_stdin = 1;
        break;
    case oDisableIpv4:
        gstate.disable_ipv4 = 1;
        break;
    case oDisableIpv6:
        gstate.disable_ipv6 = 1;
        break;
    case oEtherType:
        if (parse_hex(&n, val, sizeof(gstate.ether_type))) {
            log_error("Invalid hex value for %s: %s", opt, val);
            return EXIT_FAILURE;
        }
        gstate.ether_type = n;
        break;
    case oVerbosity:
        if (verbosity_int(val) < 0) {
            log_error("Invalid verbosity: %s", val);
            return EXIT_FAILURE;
        }
        gstate.log_verbosity = verbosity_int(val);
        break;
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
