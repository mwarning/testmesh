#ifndef _ROOT_STORAGE_0_NODES_H_
#define _ROOT_STORAGE_0_NODES_H_


#include "../utils.h" // for Address type
#include "../ext/uthash.h"

typedef struct {
    Address next_hop_addr; // use neighbor object with id and address?
    uint64_t time_updated;
    uint64_t time_created;
    uint16_t hop_count;
    UT_hash_handle hh;
} Hop;

// per destination
typedef struct {
    uint32_t id;
    uint64_t time_created;
    uint64_t time_updated;
    uint32_t seq_num; // sequence numbers are 16bit, use UINT32_MAX for unknown value
    Hop *hops;
    UT_hash_handle hh;
} Node;

Node *nodes_all();
void nodes_remove(Node *node);
Node *next_node_by_id(uint32_t id);
bool nodes_update(uint32_t id, const Address *addr, uint16_t hop_count, uint32_t seq_num, uint16_t age_bias);
void nodes_remove_next_hop_addr(const Address *addr);
void nodes_periodic();

#endif
