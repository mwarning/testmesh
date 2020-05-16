#ifndef _TRAFFIC_H_
#define _TRAFFIC_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void traffic_halving();

void send_introductions();

int traffic_add_entry(uint16_t from, uint16_t to, uint32_t bytes);
uint32_t traffic_get_entry(uint16_t from, uint16_t to);
void traffic_del_entry(uint16_t id);

void traffic_debug(FILE* out);

#endif /* _TRAFFIC_H_ */