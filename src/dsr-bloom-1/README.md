# Dynamic Source Routing - Bloom 1

Packets are broadcasted and each passing node stores its own ID in the Bloom filter (m=64, k=1) of each packet.
If a nodes identifier is in the Bloom filter of a passing packet already, then drop the packet to avoid loops.
The packet header also contains the source and destination ID.


TODO: improve based on bloom-0
