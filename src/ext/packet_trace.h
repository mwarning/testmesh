/*
 * Find a string in a payload and store that to be printed out via console.
 * This helps debugging.
 *
 * Command to send a ping packet with a marker (e.g. 'abcd') that we can track:
 *
 * ip netns exec ns-0 ping -c 1 -s4 -p$(echo -n "abcd" | hexdump -ve '1/1 "%.2x"') -I tun0 fe80::1
 */
#ifndef _PACKET_PACKET_TRACE_H_
#define _PACKET_PACKET_TRACE_H_

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

void packet_trace_set(const char *action, const uint8_t* data, size_t data_length);
void packet_trace_json(FILE* fp);

#endif // _PACKET_PACKET_TRACE_H_
