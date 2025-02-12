
#include "../main.h"
#include "../log.h"

#include "nodes.h"
#include "traffic.h"
#include "packets.h"

static uint16_t g_sequence_number = 0;


uint16_t packets_next_sequence_number()
{
	return g_sequence_number++;
}

bool packets_is_duplicate(uint32_t id, uint32_t seq_num)
{
    if (id == gstate.own_id) {
        return true;
    }

    if (seq_num == UNKNOWN_SEQUENCE_NUMBER) {
        return false;
    }

    Node *node = next_node_by_id(id);
    if (node) {
        if (is_newer_seqnum((uint16_t) node->seq_num, (uint16_t) seq_num)) {
            node->seq_num = seq_num;
            return false; // new sequence number
        } else {
            return true; // old sequence number, packet is a duplicate
        }
    } else {
        return false;
    }
}

// send and count outgoing unicast traffic
bool send_ucast_wrapper(const Address *next_hop_addr, const void* data, size_t data_len)
{
    if (next_hop_addr->family == AF_MAC) {
        send_ucast_l2(next_hop_addr, data, data_len);
    } else {
        send_ucast_l3(next_hop_addr, data, data_len);
    }

    record_traffic_by_addr(next_hop_addr, data_len, 0);

    //neighbors_send_packet(next_hop_addr, ((const uint8_t*)data)[0]);

    //Neighbor *neighbor = neighbors_get(next_hop_addr);
    //neighbor->packets_send_count += 1;
    //neighbor->packets_send_time = gstate.time_now;
    /*
    uint8_t type = ((const uint8_t*)data)[0];
    if (type == TYPE_DATA) {
        neighbor->time_send_DATA = gstate.time_now;
        //log_debug("set time_send_DATA");
    }*/

    return true;
}
