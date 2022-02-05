#ifndef _TRAFFIC_H_
#define _TRAFFIC_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Keep track of the traffic flowing. Useful for
 * debugging or even improving routing decissions.
 */

void traffic_add_bytes_out(const Address *addr, uint64_t bytes);
void traffic_add_bytes_in(const Address *addr, uint64_t bytes);
void traffic_debug(FILE* out, int argc, char *argv[]);
void traffic_cleanup();

#endif /* _TRAFFIC_H_ */