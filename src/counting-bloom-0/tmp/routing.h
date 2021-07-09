
#ifndef _DSR_BLOOM_1_H_
#define _DSR_BLOOM_1_H_

void dsr_bloom_1_tun_handler(int events, int fd); // packet from the local virtual interface 
void dsr_bloom_1_ucast_handler(int events, int fd); // received unicast packet
void dsr_bloom_1_mcast_handler(int events, int fd); // received multicast packets

int dsr_bloom_1_add_peer(FILE* fp, const char *str);
void dsr_bloom_1_init();

int dsr_bloom_1_console(FILE* file, const char *cmd);

#endif // _DSR_BLOOM_1_H_
