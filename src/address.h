#ifndef _ADDRESS_H_
#define _ADDRESS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>

// for convenience to store MAC addresses
#define AF_MAC 99


struct mac {
    uint8_t data[6];
};

struct macaddr {
    sa_family_t family;
    struct mac addr;
    uint32_t ifindex;
};

// wrapper for MAC and IP addresses
typedef union {
    sa_family_t family;
    struct macaddr mac;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
} Address;


const char *str_addr(const Address *addr);
const char *str_mac(const struct mac *addr);
uint16_t address_scope(const Address *addr);
bool address_is_zero(const Address *addr);
bool address_is_unicast(const Address *addr);
bool address_is_multicast(const Address *addr);
bool address_is_broadcast(const Address *addr);
bool address_equal(const Address *a, const Address *b);
uint32_t address_ifindex(const Address *addr);

#endif