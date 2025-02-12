
#include <assert.h>

#include "ifstates.h"
#include "neighbors.h"

#include "../log.h"

static IFState *g_ifstates = NULL;


IFState *ifstates_all()
{
	return g_ifstates;
}

IFState *ifstates_find(const uint32_t ifindex)
{
    IFState *ifstate = NULL;
    HASH_FIND(hh, g_ifstates, &ifindex, sizeof(uint32_t), ifstate);
    return ifstate;
}

void ifstates_remove(const uint32_t ifindex)
{
    IFState *ifstate = ifstates_find(ifindex);
    if (ifstate != NULL) {
        // remove entry
        HASH_DEL(g_ifstates, ifstate);
        free(ifstate);
    }
}

IFState *ifstates_create(const uint32_t ifindex)
{
    IFState *ifstate = ifstates_find(ifindex);
    if (ifstate == NULL) {
        // add new entry
        ifstate = (IFState*) calloc(1, sizeof(IFState));
        ifstate->ifindex = ifindex;
        //ifstate->interface_type = interface_type(ifindex);
        HASH_ADD(hh, g_ifstates, ifindex, sizeof(uint32_t), ifstate);
    } else {
        log_warning("ifstates_create() %s/%zu entry already exists", str_ifindex(ifindex), ifindex);
    }
    return ifstate;
}

// create non-existing entries
IFState *ifstates_get(const Address *address)
{
    uint32_t ifindex = address_ifindex(address);
    IFState *ifstate = ifstates_find(ifindex);
    return ifstate ? ifstate : ifstates_create(ifindex);
}
