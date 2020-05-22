
#ifndef _UTILS_H_
#define _UTILS_H_

// Number of elements in an array
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Size of a struct element
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))


void hexDump(const char * desc, const void * addr, const int len);

void extract_mac_from_eui64(uint8_t *mac, const struct in6_addr *addr);

int port_random(void);
int port_parse(const char pstr[], int err);
int port_set(struct sockaddr_storage *addr, uint16_t port);

int bytes_random(void *buffer, size_t size);

const char *str_addr(const struct sockaddr_storage *addr);

int addr_is_localhost(const struct sockaddr_storage *addr);
int addr_is_multicast(const struct sockaddr_storage *addr);
int addr_parse(struct sockaddr_storage *addr, const char full_addr_str[], const char default_port[], int af);
int addr_port(const struct sockaddr_storage *addr);
int addr_len(const struct sockaddr_storage *addr);
int addr_equal(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2);

int interface_set_mtu(int fd, const char *ifname, int mtu);
int interface_set_up(int fd, const char* ifname);
int interface_get_ifindex(int* ifindex, int fd, const char *ifname);
int interface_get_mac(uint8_t *mac, int fd, const char *ifname);
int tun_alloc(const char *dev);


#endif // _UTILS_H_
