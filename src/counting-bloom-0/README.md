# Counting Bloom Filter - 0

A proactive routing protocol. Every node exchanges its own Bloom filter with neighbors via COMM packets.
the received Bloom filter is degraded and then added to its own bloom filter.

Data packets are forwarded to all neighbors that have a higher propability to reach the destination.
