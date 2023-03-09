
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>


#define ARRAY_NELEMS(x) (sizeof(x) / sizeof((x)[0]))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

// Make a symbol into a string literal
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

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

typedef union {
    sa_family_t family;
    struct macaddr mac;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
} Address;

// match e.g. ["get", "1234", "foo"] with a comma separated string "get,*,foo", the asterisk matches anything
bool match(const char *argv[], const char *pattern);
uint32_t adler32(const void *buf, size_t buflen); // a hash method
void hex_dump(const char *desc, const void *buf, size_t buflen);
ssize_t bytes_random(void *buffer, size_t size); // get random bytes
uint32_t get_ip_connection_fingerprint(const uint8_t *packet, size_t length); // get unique id for IP connection pair

bool address_is_unicast(const Address *addr);
bool address_is_multicast(const Address *addr);
bool address_is_broadcast(const Address *addr);
bool address_equal(const Address *a, const Address *b);
uint32_t address_ifindex(const Address *addr);

const char *str_enabled(uint8_t enabled);
const char *str_bool(bool enabled);
const char *str_mac(const struct mac *addr);
const char *str_bytes(uint64_t bytes);
const char *str_duration(time_t from, time_t to);
const char *str_since(time_t time);
const char *str_ago(time_t time);
const char *str_addr(const Address *addr);
const char *str_addr6(const struct sockaddr_in6 *addr);

const char *str_in4(const struct in_addr *addr);
const char *str_in6(const struct in6_addr *addr);

uint32_t addr_cmp_subnet(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2, uint32_t subnet_len);
bool addr_is_localhost(const struct sockaddr_storage *addr);
bool addr_is_multicast(const struct sockaddr_storage *addr);
bool addr_is_link_local(const struct sockaddr_storage *addr);
int addr_parse(struct sockaddr_storage *addr, const char full_addr_str[], const char default_port[], uint32_t af);

#endif // _UTILS_H_
