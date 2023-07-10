#ifndef _PACKET_CACHE_H_
#define _PACKET_CACHE_H_

/*
 * This is a helper for routing protocols implementations.
 */

void packet_cache_init(uint32_t timeout);
void packet_cache_clear();

void packet_cache_add(uint32_t dst_id, void *data, size_t data_length);
void packet_cache_get_and_remove(void *data_ret, size_t *data_length_ret, uint32_t dst_id);

#endif // _PACKET_CACHE_H_