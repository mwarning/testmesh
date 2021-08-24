#ifndef _TUN_H_
#define _TUN_H_

ssize_t tun_write(uint8_t *data, ssize_t len);
ssize_t tun_read(uint32_t *dst_id, uint8_t *data, ssize_t len);

int tun_init(uint32_t id, const char *ifname);


#endif // _TUN_H_
