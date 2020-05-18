
#ifndef _OTHER_H_
#define _OTHER_H_

#include <netinet/ether.h>

int send_raw_packet(int sockfd, int ifindex, uint8_t smac[ETH_ALEN], uint8_t dmac[ETH_ALEN], const uint8_t* payload, int payload_len);

void parse_ip(const uint8_t *buf, int len);

#endif // _OTHER_H_
