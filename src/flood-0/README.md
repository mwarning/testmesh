# Flood 0

Simple flooding protocol. All packets are flooded via multicasts.

Packet header:
* transmitter (IPv6 unicast address)
* receiver (IPv6 multicast or unicast address)
* source identifier
* destination identifier
* sequence number

No state:
* node identifier
* current sequence number
