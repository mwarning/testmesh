# Flood 0

Simple flooding protocol. All packets are flooded.

Packet header:
* source identifier
* destination identifier
* sequence number

Node state:
* node identifier
* current sequence number
* last updated timestamp

Old entries are removed after a while.
