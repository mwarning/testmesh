#ifndef _ROOT_STORAGE_0_PEERS_H_
#define _ROOT_STORAGE_0_PEERS_H_

#include "../address.h"

typedef struct Peer {
    char hostname[64];
    Address address;
    struct Peer *next;
} Peer;

Peer *peers_all();

void peers_add(const char *hostname);
void peers_del(const char *hostname);

void peers_periodic();

#endif
