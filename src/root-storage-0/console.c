#include <stdbool.h>
#include <string.h>

#include "../ext/packet_trace.h"
#include "../interfaces.h"
#include "neighbors.h"
#include "ifstates.h"
#include "nodes.h"
#include "console.h"
#include "peers.h"
#include "tree.h"


bool console_handler(FILE* fp, int argc, const char *argv[])
{
   Node *g_nodes = nodes_all();
   Neighbor *g_neighbors = neighbors_all();
   IFState *g_ifstates = ifstates_all();

   if (match(argv, "h")) {
        fprintf(fp, "r                       print routing table\n");
    } else if (match(argv, "i")) {
        fprintf(fp, "node_count:      %d\n", (int) HASH_COUNT(g_nodes));
        fprintf(fp, "neighbor_count:  %d\n", (int) HASH_COUNT(g_neighbors));

        fprintf(fp, "ifstates:\n");
        IFState *ifstate;
        IFState *tmp;
        HASH_ITER(hh, g_ifstates, ifstate, tmp) {
            fprintf(fp, "  recv_own_broadcast_time:     %s ago\n", str_since(ifstate->recv_own_broadcast_time));
            //fprintf(fp, "  recv_foreign_broadcast_time: %s ago\n", str_since(ifstate->recv_foreign_broadcast_time));
            fprintf(fp, "  send_broadcast_time:         %s ago\n", str_since(ifstate->send_broadcast_time));
        }

        interfaces_debug(fp);

        Neighbor *parent = tree_get_parent(g_neighbors);

        if (parent) {
            fprintf(fp, "tree_root:\n");
            fprintf(fp, "  tree_id:        0x%08x\n", parent->root.tree_id);
            fprintf(fp, "  hop_count:      %d\n", (int) parent->root.hop_count);
            fprintf(fp, "  seq_num:        %d\n", (int) parent->root.root_seq_num);
            fprintf(fp, "  parent_id:      0x%08x\n", parent->root.parent_id);
        } else {
            Root *root = tree_get_root();
            fprintf(fp, "tree_root:\n");
            fprintf(fp, "  tree_id:        0x%08x\n", root->tree_id);
            fprintf(fp, "  hop_count:      %d\n", (int) 0);
            fprintf(fp, "  seq_num:        %d\n", (int) root->root_seq_num);
            //fprintf(fp, "  parent_id: 0x%08x\n", root->parent_id);
        }
    } else if (match(argv, "r")) {
        Node *node;
        Node *ntmp;
        Hop *hop;
        Hop *htmp;
        uint32_t node_count = 0;
        uint32_t neighbor_count = 0;

        HASH_ITER(hh, g_nodes, node, ntmp) {
            node_count += 1;
            fprintf(fp, " 0x%08x:\n", node->id);
            bool is_neighbor = false;
            HASH_ITER(hh, node->hops, hop, htmp) {
                if (hop->hop_count == 1) {
                    is_neighbor = true;
                }
                //Node *neighbor = find_neighbor_node_by_address(&hop->next_hop_addr);
                fprintf(fp, "  next-hop-address: %s, hops: %d, last-updated: %s ago\n",
                    str_addr(&hop->next_hop_addr),
                    (int) hop->hop_count,
                    //(neighbor ? neighbor->id : 0),
                    str_since(hop->time_updated)
                );
            }

            if (is_neighbor) {
                neighbor_count += 1;
            }
        }
        fprintf(fp, "%d nodes, %d neighbors\n", (int) node_count, (int) neighbor_count);
    } else if (match(argv, "n")) {
        Neighbor *neighbor;
        Neighbor *tmp;
        uint32_t count = 0;

        HASH_ITER(hh, g_neighbors, neighbor, tmp) {
            fprintf(fp, "address: %s\n",
                str_addr(&neighbor->address)
            );
            if (neighbor->ranges_set) {
                fprintf(fp,     "  ranges_span:    %"PRIu64"\n", ranges_span(&neighbor->ranges));
                fprintf(fp,     "  ranges_data:    %s\n", ranges_str(&neighbor->ranges));
            }
            if (neighbor->root_set) {
                fprintf(fp, "  tree_id:        0x%08x\n", neighbor->root.tree_id);
                fprintf(fp, "  root_hop_count: %d\n", (int) neighbor->root.hop_count);
                fprintf(fp, "  root_parent_id: 0x%08x\n", neighbor->root.parent_id);
                fprintf(fp, "  time_created:   %s\n", str_since(neighbor->root.time_created));
            }
            count += 1;
        }
        fprintf(fp, "%d neighbors\n", (int) count);
    } else if (match(argv, "peers")) {
        Peer *peer = peers_all();
        uint32_t count = 0;
        while (peer) {
            fprintf(fp, "peer: %s\n", peer->hostname);
            peer = peer->next;
            count += 1;
        }
        fprintf(fp, "%d peers\n", (int) count);
    } else if (argc == 2 && 0 == strcmp(argv[0], "peer-add")) {
        peers_add(argv[1]);
        fprintf(fp, "done\n");
    } else if (argc == 2 && 0 == strcmp(argv[0], "peer-add")) {
        peers_del(argv[1]);
        fprintf(fp, "done\n");
    } else if (match(argv, "json")) {
        Neighbor *parent = tree_get_parent(g_neighbors);
        fprintf(fp, "{\n");

        fprintf(fp, "\"own_id\": \"0x%08x\",\n", gstate.own_id);
        fprintf(fp, "\"node_count\": %d,\n", (int) HASH_COUNT(g_nodes));

        if (parent) {
            fprintf(fp, "\"tree_id\": \"0x%08x\",\n", parent->root.tree_id);
            fprintf(fp, "\"root_address\": \"%s\",\n", str_addr(&parent->address));
            fprintf(fp, "\"root_hop_count\": %d,\n", (int) parent->root.hop_count);
            fprintf(fp, "\"root_parent_id\": \"0x%08x\",\n", parent->root.parent_id);
        } else {
            Root *root = tree_get_root();
            fprintf(fp, "\"tree_id\": \"0x%08x\",\n", root->tree_id);
            fprintf(fp, "\"root_address\": \"%s\",\n", "");
            fprintf(fp, "\"root_hop_count\": %d,\n", (int) 0);
            fprintf(fp, "\"root_parent_id\": \"0x%08x\",\n", root->tree_id);
        }

        {
            fprintf(fp, "\"neighbors\": [");
            Neighbor *neighbor;
            Neighbor *neighbor_tmp;
            int neighbor_count = 0;
            HASH_ITER(hh, g_neighbors, neighbor, neighbor_tmp) {
                if (neighbor_count > 0) {
                    fprintf(fp, ", ");
                }
                neighbor_count += 1;

                fprintf(fp, "{");
                fprintf(fp, "\"is_child\": \"%s\",", str_bool(neighbor_is_child(neighbor)));
                if (neighbor->ranges_set) {
                    fprintf(fp, "\"ranges_span\": %"PRIu64",", ranges_span(&neighbor->ranges));
                    fprintf(fp, "\"ranges_data\": \"%s\",", ranges_str(&neighbor->ranges));
                }
                if (neighbor->root_set) {
                    fprintf(fp, "\"tree_id\": \"0x%08x\",", neighbor->root.tree_id);
                    fprintf(fp, "\"root_hop_count\": %d,", (int) neighbor->root.hop_count);
                    fprintf(fp, "\"root_parent_id\": \"0x%08x\",", neighbor->root.parent_id);
                    fprintf(fp, "\"time_created\": \"%s\",", str_since(neighbor->root.time_created));
                    fprintf(fp, "\"is_parent\": \"%s\",", str_bool(neighbor == parent));
                }
                fprintf(fp, "\"address\": \"%s\"", str_addr(&neighbor->address));
                fprintf(fp, "}");
            }
            fprintf(fp, "],\n");
        }

        fprintf(fp, "\"interfaces\": ");
        interfaces_debug_json(fp);
        fprintf(fp, ",\n");

        {
            fprintf(fp, "\"ifstates\": [");
            IFState *ifstate;
            IFState *ifstate_tmp;
            uint32_t ifstate_count = 0;
            HASH_ITER(hh, g_ifstates, ifstate, ifstate_tmp) {
                if (ifstate_count > 0) {
                    fprintf(fp, ", ");
                }
                ifstate_count += 1;

                fprintf(fp, "{\"ifname\": \"%s\"}", str_ifindex(ifstate->ifindex));
                //fprintf(fp, "{\"ifname\": \"%s\", \"flood_needed\": \"%s\"}",
                //    str_ifindex(ifstate->ifindex), str_bool(is_broadcast_needed_l2(ifstate)));
            }
            fprintf(fp, "],\n");
        }

        {
            fprintf(fp, "\"packet_trace\": ");
            packet_trace_json(fp);
            fprintf(fp, "\n");
        }

        fprintf(fp, "}\n");
    } else {
        return false;
    }

    return true;
}
