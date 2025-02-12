#ifndef _ROOT_STORAGE_0_TREE_H_
#define _ROOT_STORAGE_0_TREE_H_

#include <inttypes.h>
#include <stddef.h>

#include "neighbors.h"
#include "ifstates.h"
#include "packets.h"

void tree_init();

Root *tree_get_root();

void tree_periodic();
void tree_neighbor_removed(const Neighbor *neighbor);

Neighbor *tree_get_parent();

bool neighbor_is_child(const Neighbor *neighbor);

void handle_ROOT_STORE(IFState *ifstate, Neighbor *neighbor, const Address *src, uint8_t flags, ROOT_STORE *p, size_t length);
void handle_ROOT_CREATE(IFState *ifstate, Neighbor *neighbor, const Address *src, uint8_t flags, ROOT_CREATE *p, size_t length);

#endif
