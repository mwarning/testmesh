#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "address.h"
#include "utils.h"


const char *str_addr(const Address *addr)
{
    switch (addr->family) {
    case AF_INET6:
        return str_addr6((const struct sockaddr_in6 *)addr);
    case AF_INET:
        return str_addr4((const struct sockaddr_in *)addr);
    case AF_MAC:
        return str_mac((const struct mac *) &addr->mac.addr);
    default:
        return NULL;
    }
}

const char *str_mac(const struct mac *addr)
{
    static char strmacbuf[4][18];
    static size_t strmacbuf_i = 0;
    char *buf = strmacbuf[++strmacbuf_i % 4];

    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->data[0], addr->data[1], addr->data[2],
            addr->data[3], addr->data[4], addr->data[5]);

    return buf;
}

bool address_is_multicast(const Address *addr)
{
    switch (addr->family) {
    case AF_MAC: {
        const uint8_t *mac = &addr->mac.addr.data[0];
        return mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e;
    }
    case AF_INET6:
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6*) addr)->sin6_addr);
    case AF_INET:
        return IN_MULTICAST(ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr));
    default:
        log_error("address_is_multicast: invalid address");
        exit(1);
    }
}

bool address_is_broadcast(const Address *addr)
{
    static const uint8_t bmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    switch (addr->family) {
    case AF_MAC:
        return 0 == memcmp(&addr->mac.addr, &bmac[0], sizeof(bmac));
    case AF_INET6:
        // there are no broadcasts in IPv6
        return false;
    case AF_INET:
        return (ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr) & 0xff) == 0xff;
    default:
        log_error("address_is_broadcast() invalid address");
        exit(1);
    }
}

bool address_is_zero(const Address *addr)
{
    static const Address null_address = {0};
    return 0 == memcmp(&null_address, addr, sizeof(Address));
}

bool address_is_unicast(const Address *addr)
{
    return !address_is_broadcast(addr) && !address_is_multicast(addr);
}

bool address_equal(const Address *a, const Address *b)
{
    return (0 == memcmp(a, b, sizeof(Address)));
}

uint32_t address_ifindex(const Address *addr)
{
    switch (addr->family) {
    case AF_INET6:
        if (addr_is_linklocal_ipv6(&addr->ip6.sin6_addr)) {
            return addr->ip6.sin6_flowinfo;
        }
        return 0;
    case AF_INET:
        if (addr_is_linklocal_ipv4(&addr->ip4.sin_addr)) {
            return 0; // no interface available for IPv4?
        }
        return 0;
    case AF_MAC:
        return addr->mac.ifindex;
    default:
        return 0;
    }
}

/*
Highjack IPv6 multicast scope definition:
0x0     reserved
0x1     interface-local     Interface-local scope spans only a single interface on a node, and is useful only for loopback transmission of multicast.
0x2     link-local  Link-local scope spans the same topological region as the corresponding unicast scope.
0x3     realm-local     Realm-local scope is defined as larger than link-local, automatically determined by network topology and must not be larger than the following scopes.[15]
0x4     admin-local     Admin-local scope is the smallest scope that must be administratively configured, i.e., not automatically derived from physical connectivity or other, non-multicast-related configuration.
0x5     site-local  Site-local scope is intended to span a single site belonging to an organisation.
0x8     organization-local  Organization-local scope is intended to span all sites belonging to a single organization.
0xe     global  Global scope spans all reachable nodes on the internet - it is unbounded.
0xf     reserved
For unicast addresses, two scopes are defined: link-local and global.

https://en.wikipedia.org/wiki/IPv6_address#Address_scopes
*/

uint16_t address_scope(const Address *addr)
{
    switch (addr->family) {
    case AF_MAC:
        return 0x1;
    case AF_INET: {
        const struct in_addr *a = &((const struct sockaddr_in *) addr)->sin_addr;
        if (addr_is_linklocal_ipv4(a)) {
            return 0x02;
        }
        const uint8_t *address = (const uint8_t*) &addr->ip4.sin_addr;
        if ((address[0] == 192 && address[0] == 168) || (address[0] == 10)) {
            return 0x03;
        } else {
            return 0x0E;
        }
    }
    case AF_INET6: {
        const struct in6_addr *a = &((const struct sockaddr_in6 *) addr)->sin6_addr;
        if (addr_is_linklocal_ipv6(a)) {
            return 0x02;
        }
        return 0x01;
        //sin6_addr.s6_addr[]
/*
        //const uint8_t *address = (const uint8_t*) &addr->ip6.sin6_addr;
        return (a[0] == 0xFF) ||
            (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) ||
            (memcmp(a, zeroes, 15) == 0 &&
            (a[15] == 0 || a[15] == 1)) ||
            (memcmp(a, v4prefix, 12) == 0);
*/
    }
    default:
        log_error("address_scope() invalid address");
        exit(1);
    }
}

/*
bool addr_is_lan(const Address *addr)
{
    switch (addr->family) {
    case AF_INET: {
        const uint8_t *address = (const uint8_t*) &addr->ip4.sin_addr;
        return (address[0] == 192 && address[0] == 168) || (address[0] == 10);
    }
    case AF_INET6: {
        const uint8_t *address = (const uint8_t*) &addr->ip6.sin6_addr;
        return (address[0] == 0xFF) ||
            (address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
            (memcmp(address, zeroes, 15) == 0 &&
            (address[15] == 0 || address[15] == 1)) ||
            (memcmp(address, v4prefix, 12) == 0);
    }
    case AF_MAC:
        return false;
    default:
        log_error("addr_is_lan() invalid address");
        exit(1);
    }
}
*/

/*
bool addr_is_internet(const Address *addr)
{
    // TODO: this is crappy
    switch (addr->family) {
        case AF_INET:
        case AF_INET6:
            return !addr_is_lan(addr)
                && !addr_is_localhost(addr)
                && address_is_unicast(addr);
        case AF_MAC:
            return false;
        default:
            log_error("addr_is_internet() invalid address");
            exit(1);
    }
}*/
