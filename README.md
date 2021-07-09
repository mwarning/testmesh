# Geomesh - Basic Mesh Routing Protocols

A code base to quickly implement mesh routing protocols. A collection of basic protocols have been implemented already.
Included is also a OpenWrt package.

The goal is to help to develop better mesh routing protocols, so that community networks such as Freifunk can scale better.

Implemented Protocols:
- [dsr-bloom-0](src/dsr-bloom-0)
- [counting-bloom-0](src/counting-bloom-0)
- [flood-0](src/flood-0)
- [flood-1](src/flood-1)

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

## TODO

Implementation Wish List:

- AODV is the routing protocol used in ZigBee.
  - RFC3561: [Ad hoc On-Demand Distance Vector (AODV) Routing](https://tools.ietf.org/html/rfc3561)
- Vivaldi [Vivaldi: A Decentralized Network Coordinate System (2004)](https://dl.acm.org/citation.cfm?id=1015471)

## Testing

Testing can be done on real hardware or by using a network simulator (e.g. [meshnet-lab](https://github.com/mwarning/meshnet-lab)).
