# Star Routing

*This protocol is not working yet*

The nodes elect a root node that sends out a presence beacon. Every other nodes position is described as a distance (hop count) to that root.
This is a naive approach, as the distance to one node does not uniquely qualify the position of a node.

On top of that, a Distributed Hash Table (DHT) is used to resolve opaque identifiers to a position (as hop count) relative to the root node.
