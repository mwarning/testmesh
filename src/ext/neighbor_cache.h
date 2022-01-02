#ifndef _NEIGHBOR_CACHE_H_
#define _NEIGHBOR_CACHE_H_

/*
 * Map node identifier to address (MAC- or IP-address)
 */

struct Address;

const Address *neighbor_cache_lookup(uint32_t id);
void neighbor_cache_add(uint32_t id, const Address *addr);
void neighbor_cache_init(uint32_t timeout);

#endif // _NEIGHBOR_CACHE_H_