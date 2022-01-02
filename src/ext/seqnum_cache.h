#ifndef _SEQNUM_CACHE_H_
#define _SEQNUM_CACHE_H_

/*
 * Track sequence numbers to detect duplicate packets.
 */

int seqnum_cache_update(uint32_t src_id, uint16_t seq_num);
void seqnum_cache_init(uint32_t timeout);

#endif // _SEQNUM_CACHE_H_