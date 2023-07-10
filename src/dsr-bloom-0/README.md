# Dynamic Source Routing - Bloom 0

In packet Bloom filter.

Packets are always broadcasted and each passing node stores its own ID in the Bloom filter (m=64, k=1) of each packet.
If a nodes identifier is in the Bloom filter of a passing packet already, then drop the packet to avoid loops and make broadcasting efficient. The packet header also contains the source and destination ID.

Notes:
- nodes have no state
- packets are received multiple times
- no metric used

This is actually flooding.
