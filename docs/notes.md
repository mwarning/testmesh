# Development Notes

To add a new routing protocol, add:
- add a new folder `src/<routing-protocol>/routing.c`
- add a register method in `routing.h` and call `register_protocol`

Just use other protcols as template. For arrays/list/maps, feel free to use the data structures included from [ut_hash](https://troydhanson.github.io/uthash/).

Testing can be done on real hardware (using [OpenWrt](https://openwrt.org/)) or by using a network simulator (e.g. [meshnet-lab](https://github.com/mwarning/meshnet-lab)).

## Word Explanations

### Reactive vs. Proactive

A reactive routing protocols discovers routing information on demand. This might take some time initially, but has the advantage that if there is no need to send anything, then there are no requests that need to be send. This is especially useful for low traffic sensor networks.

A proactive routing protocol makes sure it has all the necessary routing information available in case a packet needs to be routed. This allows a fast initial transmission time.

### Link State vs. Distance Vector

For Link State protocols, each node tries to maintain a complete view of the network topology and it's links.
This allows for optimizations.

Distance Vector protocols (also known as Table Driven) only maintain a routing table that gives the direction of a packet to be transferred, without knowning or being in control of intermediate nodes.

There are also a lot of hybrid approaches.

## Name Independent vs. Name Dependent

Assuming the name is unique.
Also known as Opaque identifiers. If the network name can be choosen freely, then
If the name encodes the position

## LISP

Locator/Identifier Separation Protocol

## Compact Routing

Name for a research effort to reach efficient routing through LISP.

## Bi- vs. Unidirectional

Most routing protocols expect a link to allow data to flow in both directions. The link is then called bidirectional.

### Performance Metrics

Values to compare routing protocols.

## Forwarding Efficiency

Forwarding Efficiency (FE) = HopsNeeded / TotalHops

A FE value of 1 means that all packets have reached on the shortest route (according to the hop count).

## Reception Rate

Reception Rate (RR) = TotalReceived / TotalCreated

Extension of the Forwarding Efficiency. But considers all received packets and all created packets.
Makes sense to compare protocols only on identical networks.

## Packet Delivery Ratio

Packet Delivery Ratio (PDR) = PacketsArrived / PacketsGenerated

A PDR value of 1 for a pair of nodes means that all packets send from the origin have arrived at the destination.
The value is only influenced by packet loss.

## TODO

- use `htonl` to make sure tha byte order is correct on different platforms
- add internal tester/simulator
- [NS3](https://www.nsnam.org/) support
- implement AODV, it is the routing protocol used e.g. for the ZigBee.
  - RFC3561: [Ad hoc On-Demand Distance Vector (AODV) Routing](https://tools.ietf.org/html/rfc3561)
- explain what using an interface (-i) means, since we also support IP addressing
