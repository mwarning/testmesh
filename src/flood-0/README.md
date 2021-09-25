# Flood 0

Simple flooding protocol. All packets are broadcasted and flooed throughout the entire network.
WiFi broadcasts are about \~20 times slower compared to unicast.

Packet header:
* source identifier
* destination identifier
* sequence number

Node state:
* node identifier
* current sequence number
* last updated timestamp

Old entries are removed after a while.
