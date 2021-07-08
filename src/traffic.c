#include <string.h>

#include "utils.h"
#include "tree/neighbors.h"
#include "log.h"
#include "traffic.h"


typedef struct {
    // id 0 means not set
    // id 1 is self
    uint16_t from; // 0 means any
    uint16_t to; // 
    uint32_t bytes;
    // TODO: use traffic in the last minute..
} Traffic;

static Traffic g_traffic[200] = {0};

int is_active_entry(const Traffic *tr)
{
    return tr->from != 0 && tr->to != 0;
}

/*
void send_introductions()
{
    for (int i = 0; i < ARRAY_NELEMS(g_traffic); i += 1) {
        if (count_neighbors() > 10) {
            break;
        }

        // threshold
        if (g_traffic[i].bytes < 100) {
            continue;
        }

        if (!is_active_entry(&g_traffic[i])) {
            continue;
        }

        send_introduction(g_traffic[i].from, g_traffic[i].to);
    }
}*/

int traffic_add_entry(uint16_t from, uint16_t to, uint32_t bytes)
{
    if (from == 0 || to == 0) {
        log_error("invalid from/to");
        exit(1);
    }

    int first_free_entry = -1; //first
    for (int i = 0; i < ARRAY_NELEMS(g_traffic); i += 1) {
        Traffic *traffic = &g_traffic[i];
        if (traffic->from == 0 && first_free_entry == -1) {
            first_free_entry = i;
        } else if (traffic->from == from && traffic->to == to) {
            traffic->bytes += bytes;
            // updated
            return traffic->bytes;
        }
    }

    if (first_free_entry != -1) {
        Traffic *traffic = &g_traffic[first_free_entry];
        traffic->from = from;
        traffic->to = to;
        traffic->bytes = bytes;
        // added
        return bytes;
    } else {
        // no space to keep information...
        return 0;
    }
}

uint32_t traffic_get_entry(uint16_t from, uint16_t to)
{
    uint32_t sum = 0;
    for (int i = 0; i < ARRAY_NELEMS(g_traffic); i += 1) {
        Traffic *traffic = &g_traffic[i];
        if (from == 0) {
            if (to == 0 || traffic->to == to)  {
                sum += traffic->bytes;
            }
        } else {
            if (from == 0) {
                sum += traffic->bytes;
            }
            if (traffic->from == from) {
                return traffic->bytes;
            }
        }
    }

    return sum;
}

void traffic_halving()
{
    for (int i = 0; i < ARRAY_NELEMS(g_traffic); i += 1) {
        Traffic *traffic = &g_traffic[i];
        traffic->bytes /= 2;

        // effectively delete entry if bytes reaches 0
        if (traffic->bytes == 0) {
            traffic->from = 0;
            traffic->to = 0;
        }
    }
}

void traffic_del_entry(uint16_t id)
{
    for (int i = 0; i < ARRAY_NELEMS(g_traffic); i += 1) {
        Traffic *traffic = &g_traffic[i];
        if (traffic->from == id || traffic->to == id) {
            memset(traffic, 0, sizeof(Traffic));
        }
    }
}

void traffic_debug(FILE* out)
{
    char buf[64];
    int count = 0;
    fprintf(out, "  from => to (bytes)\n");
    for (int i = 0; i < ARRAY_NELEMS(g_traffic); i += 1) {
        Traffic *traffic = &g_traffic[i];
        if (traffic->from != 0) {
            fprintf(out, "  %u => %u (%s)\n",
                traffic->from,
                traffic->to,
                format_size(buf, traffic->bytes)
            );
            count += 1;
        }
    }
    fprintf(out, "%d entries\n", count);
}