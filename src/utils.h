
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>
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
    int ifindex; // needed? - we can also use the sender mac.
};

typedef union {
    sa_family_t family;
    struct macaddr mac;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
} Address;

uint32_t adler32(const void *buf, size_t buflength);
void hex_dump(const char *desc, const void *addr, const int len);

int bytes_random(void *buffer, size_t size);

const char *address_type_str(const Address *addr);
void init_macaddr(Address *dst, const void *mac_addr, int ifindex);

const char *str_addr2(const Address *addr);
const char *str_addr6(const struct sockaddr_in6 *addr);

const char *str_in4(const struct in_addr *addr);
const char *str_in6(const struct in6_addr *addr);

int add_addr6(struct in6_addr *addr, int prefixlen, unsigned ifindex);
int del_addr6(struct in6_addr *addr, int prefixlen, unsigned ifindex);

int addr_cmp_subnet(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2, int subnet_len);
int addr_is_localhost(const struct sockaddr_storage *addr);
int addr_is_multicast(const struct sockaddr_storage *addr);
int addr_is_link_local(const struct sockaddr_storage *addr);
int addr_parse(struct sockaddr_storage *addr, const char full_addr_str[], const char default_port[], int af);
int addr_port(const struct sockaddr_in6 *addr);
int addr_len(const struct sockaddr_storage *addr);
int addr_equal(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2);
int addr_equal6(const struct in6_addr *addr1, const struct in6_addr *addr2);

const char *format_mac(char buf[18], const struct mac *addr);
const char *format_duration(char buf[64], time_t from, time_t to);
const char *format_size(char buf[64], unsigned bytes);

#endif // _UTILS_H_
