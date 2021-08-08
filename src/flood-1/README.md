# Flood 1

Simple flooding protocol. Packets are send by unicast if the destination is known via the shorted route (hop count metric). Peers over the Internet are supported.

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
