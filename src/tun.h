#ifndef _TUN_H_
#define _TUN_H_

// write IP packet to tun0
ssize_t tun_write(uint8_t *buf, ssize_t buflen);

// read IP packet from tun0
ssize_t tun_read(uint32_t *dst_id, uint8_t *buf, ssize_t buflen);

int tun_init(uint32_t id, const char *ifname);


#endif // _TUN_H_
