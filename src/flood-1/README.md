# Flood 1

Simple flooding protocol. Packets are send by unicast if the destination is known via the shortest route (hop count metric). The algorithm is similar to AODV.

Packet header:
* source identifier
* destination identifier
* sequence number
* hop counter

Node state for each known node:
* node identifier
* best metric
* current sequence number
* last updated timestamp

Old entries are removed after a while.
