# Mesh Routing Protocol Example

This is an example implementation of a mesh routing protocol.
The entry point to the network is a tun interface (usually `tun0`).

To find peer nodes, a (IPv6) multicast packet is send on each configured interface every few seconds.
Packets (IPv4+IPv6) on the tun0 interface will be send to all other peers.

```
./geomesh -i wlan0 -i eth0 -c 1.2.3.4
```

Here, automatic discovery for local peers is performed on interfaces `wlan0` and `eth0`. One explicit peer `1.2.3.4` is given. At least one interface or peer should be given for a meaningful operation.

If at least two peers are connected, they can send arbitrary IP traffic to each other. IP multicast traffic is filtered out if not enabled.

Packet that are too big might cause problems.

AODV is the routing protocol used in ZigBee.

- RFC3561: [Ad hoc On-Demand Distance Vector (AODV) Routing](https://tools.ietf.org/html/rfc3561)
