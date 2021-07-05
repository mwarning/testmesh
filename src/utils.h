
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

// Number of elements in an array
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ARRAY_NELEMS(x) (sizeof(x) / sizeof((x)[0]))

// Size of a struct element
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

/*
struct address {
	union {
		short ss_family;
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	};
};*/
uint32_t adler32(const void *buf, size_t buflength);
void hexDump(const char * desc, const void * addr, const int len);

int is_eui64(const struct in6_addr *addr);
int is_eui64_sockaddr(struct sockaddr *addr);
void extract_mac_from_eui64(uint8_t *mac, const struct in6_addr *addr);
int interface_get_addr6(struct in6_addr /*sockaddr_in6*/ *addr, const char *ifname);

int port_random(void);
int port_parse(const char pstr[], int err);
int port_set(struct sockaddr_storage *addr, uint16_t port);
int port_set6(struct sockaddr_in6 *addr, uint16_t port);

int bytes_random(void *buffer, size_t size);

const char *str_addr(const struct sockaddr_storage *addr);
const char *str_addr6(const struct sockaddr_in6 *addr);
const char *str_in6(const struct in6_addr *addr);

const char *str_ifindex(int ifindex);

int add_addr6(struct in6_addr *addr, int prefixlen, unsigned ifindex);
int del_addr6(struct in6_addr *addr, int prefixlen, unsigned ifindex);

int addr_cmp_subnet(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2, int subnet_len);
int addr_is_localhost(const struct in6_addr *addr);
int addr_is_multicast(const struct in6_addr *addr);
int addr_is_link_local(const struct sockaddr_storage *addr);
int addr_parse(struct sockaddr_storage *addr, const char full_addr_str[], const char default_port[], int af);
int addr_port(const struct sockaddr_in6 *addr);
int addr_len(const struct sockaddr_storage *addr);
int addr_equal(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2);
int addr_equal6(const struct in6_addr *addr1, const struct in6_addr *addr2);
int addr_equal66(const struct sockaddr_in6 *addr1, const struct sockaddr_in6 *addr2);

int interface_set_mtu(int fd, const char *ifname, int mtu);
int interface_set_up(int fd, const char* ifname);
int interface_get_ifindex(int* ifindex, int fd, const char *ifname);
int interface_get_mac(uint8_t *mac, int fd, const char *ifname);
int tun_alloc(const char *dev);

int interface_is_up(int fd, const char *interface);

char *format_duration(char buf[64], time_t from, time_t to);
char *format_size(char buf[64], unsigned bytes);

int addr_set(const char *ifname, const struct in6_addr *addr);
int addr_del(const char *ifname, const struct in6_addr *addr);
int addr_flush(const char *ifname);

void id_get4(uint32_t *id, const struct in_addr *addr);
void id_set4(struct in_addr *addr, const uint32_t *id);
void id_get6(uint32_t *id, const struct in6_addr *addr);
void id_set6(struct in6_addr *addr, const uint32_t *id);


int is_martian(const struct sockaddr *sa);
ssize_t recv6_fromto(int fd, void *buf, size_t len, int flags, int *ifindex, struct sockaddr_storage *from, struct sockaddr_storage *to);

#endif // _UTILS_H_
