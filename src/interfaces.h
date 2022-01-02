#ifndef _INTERFACES_H_
#define _INTERFACES_H_

#include <linux/if_ether.h>   // ETH_ALEN(6), ETH_HLEN(14), ETH_FRAME_LEN(1514), struct ethhdr

void interfaces_init();
int interfaces_debug(FILE *fd);

const char *str_ifindex(unsigned ifindex);

// TODO: use, get ifindex by name (0 on error)
//unsigned interface_get_ifindex_by_name(const char *ifname);

// get ifindex a socket is bound to (0 on error)
unsigned interface_get_ifindex(int fd);
//struct mac interface_get_ifmac(int fd);

// register interface (only layer 2 right now)
int interface_add(const char *ifname);
int interface_del(const char *ifname);

// send to an IP address (e.g. over Internet)
//void send_ucast_l3(const struct sockaddr_storage *addr, const void *data, size_t data_len);

// send as Ethernet packet (e.g. over mesh WiFi)
void send_bcasts_l2(const void* data, size_t data_len);
int send_ucast_l2(const Address *addr, const void* data, size_t data_len);

/*
// send as IPv6 multicast (deprecated?)
void send_mcasts_l3(const void* data, int data_len);
int send_mcast_l3(unsigned ifindex, const void* data, int data_len);

ssize_t recv6_fromto(int fd, void *buf, size_t len, int flags, unsigned *ifindex, struct sockaddr_storage *from, struct sockaddr_storage *to);
*/

#endif /* _INTERFACES_H_ */