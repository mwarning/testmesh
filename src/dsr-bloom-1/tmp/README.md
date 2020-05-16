# Dynamic Source Routing - Bloom 0

Packets are broadcasted and each passing node stores its own ID in the Bloom Filter of each packet.
If a nodes identifier is in the Bloom filter already, then drop the packet to avoid loops.
