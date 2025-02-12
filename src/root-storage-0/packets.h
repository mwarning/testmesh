#ifndef _ROOT_STORAGE_0_PACKETS_H_
#define _ROOT_STORAGE_0_PACKETS_H_

#include <inttypes.h>
#include <stddef.h>

#include "../ext/uthash.h"
#include "../utils.h"

#include "ranges.h"

enum {
    TYPE_DATA,

    TYPE_ROOT_CREATE,
    TYPE_ROOT_STORE,

    TYPE_RREQ,
    TYPE_RREP,
    TYPE_RREP2,
    TYPE_PING,
    TYPE_PONG,
    TYPE_RERR,

    TYPE_NETWORK_SHORTCUT_IPV4,
    TYPE_NETWORK_SHORTCUT_IPV6,
};

//static bool g_root_enable = true;
/*
enum ROOT_SETTING {
    ROOT_SETTING_NO, // never send a ROOT packet
    ROOT_SETTING_YES, //
    ROOT_SETTING_MAYBE, // send root if not other ROOT is there
};
*/

enum FLAGS {
    FLAG_IS_BROADCAST = 1,
    FLAG_IS_UNICAST = 2,
    FLAG_IS_DESTINATION = 4,
};

#define ENABLE_SEND_RREP2 true

// Send root create packet only if the neighborhood changed or a neighbor needs it (we received our own broadcast!).
// not used atm.
#define ENABLE_OPTIMIZED_ROOT_CREATE false

// Send client list only in increasing intervals. Interval is reset if parent changes.
#define ENABLE_OPTIMIZED_ROOT_STORE false

// Replace broadcast with multiple unicasts if there very few neighbors in a broadcast domain.
#define ENABLE_OPTIMIZED_BROADCAST false

#define HOP_TIMEOUT_MS (8 * 1000)

#define UNKNOWN_SEQUENCE_NUMBER UINT32_MAX

typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t payload_length;
    uint8_t payload_data[];
} DATA;

typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
} RREQ;

// response to a RREQ from destination node
typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
} RREP;

// response to a RREQ (but from a any node)
typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
    uint32_t req_id; // dst_id from RREQ
    uint16_t req_seq_num;
    uint8_t req_hops;  // hop distance of req_id from src_id
    uint8_t req_age_exp; // age of routing information in seconds
} RREP2;

typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint16_t seq_num;
    uint8_t hop_count;
    uint32_t src_id;
    uint32_t dst_id;
    uint32_t unreachable_id;
} RERR;

// used to probe a neighbor is still alive
typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint16_t seq_num;
} PING;

typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint16_t seq_num;
} PONG;

typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint8_t hop_count;
    uint8_t bandwidth;
    uint16_t root_seq_num;
    uint16_t next_send_ms;
    // uint8_t neighbor_count;
    // uint8_t stored_nodes;
    // uint8_t has_public_address_ip; // the direct neighbors can verify this
    uint32_t tree_id; // use a random id? it does not need to be the actual id
    // for optimized broadcasts - may only be the lowest part of an ID
    uint32_t sender;
    uint32_t prev_sender;
} ROOT_CREATE;

typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint8_t data[1500 - 2];
} ROOT_STORE;

// TODO: use
typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint16_t seq_num;
    uint8_t address[4];
} NETWORK_SHORTCUT_IPV4;

// TODO: use
typedef struct __attribute__((__packed__)) {
    uint16_t type;
    uint16_t seq_num;
    uint8_t address[16];
} NETWORK_SHORTCUT_IPV6;


uint16_t packets_next_sequence_number();
bool packets_is_duplicate(uint32_t id, uint32_t seq_num);

bool send_ucast_wrapper(const Address *next_hop_addr, const void* data, size_t data_len);

#endif
