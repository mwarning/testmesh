#ifndef _INTERFACES_H_
#define _INTERFACES_H_

#include <linux/if_ether.h>   // ETH_ALEN(6), ETH_HLEN(14), ETH_FRAME_LEN(1514), struct ethhdr

void interfaces_init();
int interfaces_debug(FILE *fd);

const char *str_ifindex(unsigned ifindex);

// register interface (only layer 2 right now)
int interface_add(const char *ifname);
int interface_del(const char *ifname);

// send as Ethernet packet (e.g. over mesh WiFi)
void send_bcasts_l2(const void* data, size_t data_len);
int send_ucast_l2(const Address *addr, const void* data, size_t data_len);

// send as IP packet (UDP)
void send_ucast_l3(const Address *addr, const void *data, size_t data_len);
int send_mcast_l3(const Address *addr, const void *data, size_t data_len);

#endif /* _INTERFACES_H_ */