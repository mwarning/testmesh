
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
void hexDump(const char * desc, const void * addr, const int len);

int bytes_random(void *buffer, size_t size);

int parse_ip_packet(uint32_t *dst_id, const uint8_t *buf, ssize_t read_len);

const char *address_type_str(const Address *addr);
void set_macaddr(Address *dst, const uint8_t *addr, int ifindex);

int is_eui64(const struct in6_addr *addr);
int is_eui64_sockaddr(struct sockaddr *addr);
void extract_mac_from_eui64(uint8_t *mac, const struct in6_addr *addr);
int interface_get_addr6(struct in6_addr /*sockaddr_in6*/ *addr, const char *ifname);

const char *str_addr2(const Address *addr);

const char *str_addr6(const struct sockaddr_in6 *addr);

const char *str_in4(const struct in_addr *addr);
const char *str_in6(const struct in6_addr *addr);

const char *str_ifindex(int ifindex);

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
int addr_equal66(const struct sockaddr_in6 *addr1, const struct sockaddr_in6 *addr2);

int interface_set_mtu(int fd, const char *ifname, int mtu);
int interface_set_up(int fd, const char* ifname);

int interface_is_up(int fd, const char *interface);

const char *format_mac(char buf[18], const struct mac *addr);
const char *format_duration(char buf[64], time_t from, time_t to);
const char *format_size(char buf[64], unsigned bytes);

uint32_t id_get4(const struct in_addr *addr);
void id_set4(struct in_addr *addr, uint32_t id);
uint32_t id_get6(const struct in6_addr *addr);
void id_set6(struct in6_addr *addr, uint32_t id);

int is_martian(const struct sockaddr *sa);

#endif // _UTILS_H_
