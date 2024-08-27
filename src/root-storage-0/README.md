# Root-Storage 0

A spanning tree protocol. It is mixed proactive/reactive. The focus is on scalability.

On startup, the nodes selects a root node (ROOT_CREATE packet).
In intervals, each node sends a list of all IDs received via child nodes and its own ID to the parent node towards the root (ROOT_STORE packet). If the list of IDs do not fit in a packet, then the IDs that cause for the biggest size increase of ROOT_STORE packet are discarded. In ROOT_STORE IDs are stored as ranges. In can happen that overlapping ranges send from multiple children since the range compression not only drops IDs but also extend ranges if they are "close". The main metric is size.

Each node has three basic data structures, one for the direct neighbors (g_neighbors) and one for nodes and their next hops (g_nodes).

If the next hop for an ID is not known, send a RREQ packet to discover the route.
RREQ packets are routed via the list of stored IDs for each neighbor (in g_neighbor). If no child is found, then the RREQ is routed to the parent, ultimately reaching the root node.
DATA packet are only routed via the g_nodes next hop entries.

TODO:
* make timings adaptive and per hop?

hm..., add field to RREQ to store the lowest "route timeout" and then select the lowest value?
But then, do we expect the timeout to be different anyway?

