# Flood 1

Simple flooding protocol. Packets are send by unicast if the destination is known.

Packet header:
* transmitter (IPv6 unicast address)
* receiver (IPv6 multicast or unicast address)
* source identifier
* destination identifier
* sequence number
* hop counter

Node state for each known node:
* node identifier
* last updated time
* best metric
* current sequence number

Node state entries have a timeout.
