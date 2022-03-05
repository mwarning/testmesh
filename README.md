# Testmesh - Basic Mesh Routing Protocols

A code base to quickly implement mesh routing protocols. A collection of basic protocols have been implemented already.
Included is also a OpenWrt package that is ready to be used in real networks, albeit not being production ready.

The goal of this project is to help to develop better mesh routing protocols, so that community networks such as Freifunk can scale better.

Note: These implementations use simplified algorithms that do not adhere to any technical publication.

Implemented Protocols:

- [flood-0](src/flood-0/)
  - reactive
  - sequence number
  - broadcast only
  - no metric
- [aodv-0](src/aodv-0/)
  - reactive
  - sequence number
- [dsr-0](src/dsr-0/)
  - reactive
  - sequence number
  - uses paths of MAC/IP
- [dsr-bloom-0](src/dsr-bloom-0/)
  - reactive
  - Bloom filter in packet
  - nodes have no state
  - only bradcast
- [dsr-bloom-1](src/dsr-bloom-1/)
  - reactive
  - Bloom filter in packet
  - nodes store Bloom filters of neighbbors
  - switches between bradcast and unicast
- [counting-bloom-0](src/counting-bloom-0/)
  - proactive
  - counting Bloom filter
  - degrade filter on every hop
  - send routing information as one hop bradcast to neighbors
  - send payload as unicast along gradient
- [star-0](src/star-0/)
  - incomplete!
  - reactive
  - route via distance to a single root
  - uses a naive DHT
- [vivaldi-0](src/vivaldi-0/)
  - incomplete!
  - proactive
- [trees-0](src/streets-0/)
  - incomplete!
  - spanning tree
  - proactive

Notes:
 - 32Bit node identifiers are mapped to and from IP addresses
 - the hop count metric is used in all examples
 - DSR stands for Dynamic Source Routing
 - AODV stands for Ad-hoc Distance Vector
 - the number after a routing protocol name differentiates variants

## Usage

```
./testmesh -p flood-0 -i wlan0
```

Since multiple protocols are available, a protocol must be specified at startup.
Otherwise the list of available protocols is printed.

Use the `tun0` interface to exchange packets with other instances.

```
$ ./build/testmesh -h
Usage: testmesh -i eth0 -i wlan0

  --protocol,-p <protocol>    Select routing protocol
  --daemon,-d                 Run as daemon
  --interface,-i <interface>  Limit to given interfaces
  --find-interfaces           Find and add interfaces automatically
  --own-id <id>               Identifier of this node (default: <random>)
  --gateway-id <id>           Identifier of the gateway node (default: <none>)
  --peer <address>            Add a peer manually by address
  --control,-c <path>         Control socket to connect to a daemon
  --tun-name <ifname>         Network entry interface, use none to disable (Default: tun0)
  --tun-setup <1/0>           Auto configure entrey interface with IP address (Default: 1)
  --ether-type <hex>          Ethernet type (Default: 88B5)
  --log-file,-lf <path>       Write log output to file
  --log-level,-ll <level>     Log level. From 0 to 6 (Default: 3).
  --log-timestamp,-lt         Add timestamps to log output.
  --disable-stdin             Disable interactive console on startup
  --enable-ipv4,-4 <0/1>      Enable IPv4 (Default: 0)
  --enable-ipv6,-6 <1/0>      Enable IPv6 (Default: 1)
  --help,-h                   Prints this help text
  --version                   Print version

Valid protocols: dsr-0, flood-0, ...
```

## Daemon Control

If testmesh is started with the control socket option (`testmesh -c /tmp/testmesh.sock`), the instance can be controlled remotely:

```
testmesh-ctl -c /tmp/testmesh.sock
```

or use `socat`:

```
socat - UNIX-CONNECT:/tmp/testmesh.sock
```

## Further Reading

* [Development Notes](docs/notes.md)
* [Whish List](docs/whishes.md)

## Other Mobile Ad-hoc Network Protocols

Some popular or interesting Mobile Ad-hoc mesh routing protocols.

* [OLSR](https://datatracker.ietf.org/doc/html/rfc3626) (proactive, Link State)
* [Batman-adv](https://www.open-mesh.org/projects/batman-adv/wiki/Wiki) (proactive, Distance Vector)
* [Babel](https://www.irif.fr/~jch/software/babel/) (proactive, Distance Vector)
* [Yggdrasil](https://yggdrasil-network.github.io/) (Spanning Tree/Distance Vector)

Interesting projects for low bandwidth networks:

* [Disaster Radio](https://disaster.radio/)
* [GoTenna](https://gotenna.com/)
* [Meshtastic](https://meshtastic.org/)
* [Reticulum](https://unsigned.io/projects/reticulum/)
