#ifndef _ROOT_STORAGE_0_ROOT_H_
#define _ROOT_STORAGE_0_ROOT_H_

#include <inttypes.h>

// Idea
// * measure missed packets via sequence number
// * do not use root_id, but only for debugging
// * use latency to replace hop_count?
typedef struct {
	// Tree identifier. It is not used for root selection!
    uint32_t tree_id;
    uint16_t hop_count;
    uint8_t bandwidth; // interface type enum value
    uint16_t root_seq_num;
    uint64_t root_recv_time;
    uint64_t root_send_time; //needed?
    uint32_t parent_id; // for debugging

    uint16_t root_next_send_ms; // next send (or earlier?)

    uint64_t store_send_time; // needed?
    uint32_t store_send_counter;
    uint64_t time_created; // or use neighbor creation time?
} Root;

// TODO: move root handlers function here

#endif