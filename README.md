# Geomesh - Basic Mesh Routing Protocols

A code base to quickly implement mesh routing protocols. A collection of basic protocols have been implemented already.
Included is also a OpenWrt package.

The goal is to help to develop better mesh routing protocols, so that community networks such as Freifunk can scale better.

Implemented Protocols:

- [flood-0](src/flood-0/)
  - reactive
  - sequence number
  - only multicast
  - no metric
- [flood-1](src/flood-1/)
  - reactive
  - sequence number
  - switch between multicast and unicast
  - hop count metric
- [dsr-bloom-0](src/dsr-bloom-0/)
  - reactive
  - Bloom filter in packet
  - nodes have no state
  - only multicast
- [dsr-bloom-1](src/dsr-bloom-1/)
  - reactive
  - Bloom filter in packet
  - Bloom filters are recorded by neighbbor
  - switches between multicast and unicast
- [counting-bloom-0](src/counting-bloom-0/)
  - proactive
  - couting Bloom filter
  - degrade filter on every hop
  - send routing information as one hop multicast to neihgbors
  - send payload as unicast along gradient
- [vivaldi-0](src/vivaldi-0/)
  - proactive
  - incomplete!

Notes:
 - the numbers differentiate between variants
 - DSR stands for Dynamic Source Routing (the path is encoded in the packet)

## Usage

```
./geomesh -p flood-0 -i wlan0
```

Since multiple protocols are available, a protocol must be specified at startup.
Otherwise a list of available protocols is printed.

## Daemon Control

If geomesh is started as daemon (`-d`), a control socket can be used `./geomesh ... -s /tmp/geomesh.sock` to inspect the state.

```
geomesh-ctl -s /tmp/geomesh.sock
```

or use `socat`:

```
socat - UNIX-CONNECT:/tmp/geomesh.sock
```

## Development Notes

To add a new routing protocol, add:
- add a new folder `src/<routing-protocol>/routing.c`
- add a register method in `routing.h` and call `register_protocol`

Just use other protcols as template. For arrays/list/maps, feel free to use the data structures included from [ut_hash](https://troydhanson.github.io/uthash/).

Testing can be done on real hardware (using [OpenWrt](https://openwrt.org/)) or by using a network simulator (e.g. [meshnet-lab](https://github.com/mwarning/meshnet-lab)).

## TODO

- use `htonl` to make sure tha byte order is correct on different platform
- add internal tester/simulator
- [NS3](https://www.nsnam.org/) support
- implement AODV, it is the routing protocol used e.g. for the ZigBee.
  - RFC3561: [Ad hoc On-Demand Distance Vector (AODV) Routing](https://tools.ietf.org/html/rfc3561)
