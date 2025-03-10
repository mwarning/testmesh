#ifndef _INTERFACES_H_
#define _INTERFACES_H_

#include <inttypes.h>
#include <stdio.h> // FILE
#include <linux/if_ether.h>   // ETH_ALEN(6), ETH_HLEN(14), ETH_FRAME_LEN(1514), struct ethhdr

#include "main.h" // enum FIND_INTERFACES
#include "address.h"

// useful as interface hint for bandwidth and MTU
enum INTERFACE_TYPE {
    INTERFACE_TYPE_UNKNOWN, // valid, but unknown properties
    INTERFACE_TYPE_LORA, // wireless + very low bandwidth
    INTERFACE_TYPE_BLUETOOTH, // wireless + low bandwidth
    INTERFACE_TYPE_WLAN, // wireless + high bandwidth
    INTERFACE_TYPE_LAN,  // wired + very high bandwidth
};

const char *str_find_interfaces(int value);

bool interfaces_init();
void interfaces_debug(FILE *fd);
void interfaces_debug_json(FILE *fd);

const char *str_ifindex(unsigned ifindex);
enum INTERFACE_TYPE get_interface_type(const uint32_t ifindex);

// register interface (only layer 2 right now)
bool interface_add(const char *ifname);
bool interface_del(const char *ifname);

// send as Ethernet packet (e.g. over mesh WiFi)
void send_bcast_l2(const uint32_t ifindex, const void* data, size_t data_len);
bool send_ucast_l2(const Address *addr, const void* data, size_t data_len);

// send as IP packet (UDP)
void send_ucast_l3(const Address *addr, const void *data, size_t data_len);
bool send_mcast_l3(const Address *addr, const void *data, size_t data_len);

#endif /* _INTERFACES_H_ */