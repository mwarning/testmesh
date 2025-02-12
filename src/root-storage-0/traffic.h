#ifndef _ROOT_STORAGE_0_TRAFFIC_H_
#define _ROOT_STORAGE_0_TRAFFIC_H_

#include <inttypes.h>
#include <stddef.h>

#include "../address.h"

#define TRAFFIC_DURATION_SECONDS 8


typedef struct {
    uint64_t updated_time;
    uint32_t out_bytes[TRAFFIC_DURATION_SECONDS];
    uint32_t in_bytes[TRAFFIC_DURATION_SECONDS];
} Traffic;

void record_traffic(Traffic *traffic, uint32_t in_bytes, uint32_t out_bytes);
void record_traffic_by_addr(const Address *src, uint32_t out_bytes, uint32_t in_bytes);

#endif
