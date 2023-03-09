#ifndef _TUN_H_
#define _TUN_H_

// write IP packet to tun0
ssize_t tun_write(void *buf, ssize_t buflen);

// read IP packet from tun0
ssize_t tun_read(uint32_t *dst_id, void *buf, ssize_t buflen);

int tun_init(uint32_t id, const char *ifname);

// statistics
uint64_t tun_read_count();
uint64_t tun_write_count();
uint64_t tun_read_bytes();
uint64_t tun_write_bytes();

#endif // _TUN_H_
