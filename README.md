# Testmesh - Basic Mesh Routing Protocols

A code base to quickly implement mesh routing protocols in C. Included is also a OpenWrt package that is ready to be used in real networks.

The goal of this project is to help to develop better mesh routing protocols, so that community networks such as [Freifunk](https://freifunk.net) scale better.

Note: These implementations...
* are highly experimental
* do not adhere to any technical publication
* do not care about byte ordering (Endianness)
* are single threaded for simplicity (but use non-blocking I/O)

Implemented Protocols:

- [flood-0](src/flood-0/)
  - reactive
  - sequence number
  - broadcast only
  - no metric
- [flood-1](src/flood-1/)
  - like food-0
  - uses critical nodes
- [aodv-0](src/aodv-0/)
  - reactive
  - sequence number
- [aodv-1](src/aodv-1/)
  - like aodv-0
  - intermediate nodes answer route requests as well
- [aodv-bloom-0](src/aodv-bloom-0/)
  - imcomplete!
  - like aodv-1
  - uses bloom filters
  - stores multiple paths for a destination
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
  - like dsr-bloom-0
  - nodes store Bloom filters of neighbbors
  - switches between bradcast and unicast
- [counting-bloom-0](src/counting-bloom-0/)
  - proactive
  - counting Bloom filter
  - degrade filter on every hop
  - send routing information as one hop bradcast to neighbors
  - send payload as unicast along gradient
- [ratelimit-0](src/ratelimit-0/)
  - reactive
  - distance vector
  - rate limit broadcast/discovery packet by other traffic
  - dynamic node timeout
- [ratelimit-1](src/ratelimit-1/)
  - like ratelimit-0
  - other nodes can reply to route request
- [ratelimit-2](src/ratelimit-2/)
  - like ratelimit-2
  - utilize full/partial flood RREQ
 [ratelimit-3](src/ratelimit-3/)
  - like ratelimit-3
  - add dead node detection and accumulate RREQ
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
- [streets-0](src/streets-0/)
  - incomplete!
  - proactive
- [root-storage-0](src/root-storage-0/)
  - incomplete!
  - proactive

Notes:
 - 32Bit node identifiers are mapped to and from IP addresses
 - the hop count metric is used in all examples (yet)
 - all protocols here use Ethernet packets / layer-2 to communicate
 - the implementations assume no bad behaving participants or threat actors
 - the protocol code is not endianess safe (yet)
 - `DSR` stands for `Dynamic Source Routing`
 - `AODV` stands for `Ad-hoc On-demand Distance Vector`
 - the number after a routing protocol name is for variants

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

  --protocol,-p <protocol>        Select routing protocol
  --daemon,-d                     Run as daemon in background
  --interface,-i <interface>      Limit to given interfaces
  --find-interfaces [on/off/auto] Find and add interfaces automatically (default: off)
  --own-id <id>                   Identifier of this node (default: <random>)
  --gateway-id <id>               Identifier of the gateway node (default: <none>)
  --config <file>                 Configuration file (default: <none>).
  --control,-c <path>             Control socket to connect to a daemon
  --tun-name <ifname>             Network entry interface, use none to disable (default: tun0)
  --tun-setup <on/off>            Auto configure entry interface with IP address (default: on)
  --ether-type <hex>              Ethernet type for layer-2 packets (default: 0x88B5)
  --log-file,-lf <path>           Write log output to file
  --log-level,-ll <level>         Log level: mute, error, warning, info, verbose, debug, trace (default: info)
  --log-time,-lt                  Add timestamps to logging output
  --disable-stdin                 Disable interactive console on startup
  --enable-ipv4,-4 <on/off>       Enable IPv4 (default: off)
  --enable-ipv6,-6 <on/off>       Enable IPv6 (default: on)
  --help,-h                       Print this help text
  --version                       Print version

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

## Configure WLAN Interfaces for meshing

Usually we want to write data to an interface and expect it to be received by all other devices on the other end (be it radio or cable). There are several ways to do this.

### Ad-Hoc

* bad driver support by WLAN vendors
* bad MAC layer

Pro: old standard
Cons: often disfunctional driver support

### 802.11s

* standardized
* disable meshing to run your own algorithm on top

Pro: widespread and much better support compared to Ad-Hoc
Cons: driver support might still not be ideal

### AP-Mode Meshing

APuP (Access Point Micro Peering) allows an AP to talk other APs in the vicinity without separate mesh interface / SSID.

Pro: no need for driver and Linux kernel modification
Cons: experimental

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
* [Hyperspace](https://github.com/kurthildebrand/hyperspace)

When Ad-Hoc mode or 802.11s is not stable or available:

* [WiFi meshing on Android](https://github.com/UstadMobile/Meshrabiya)
* [AP mode WiFi mesh on OpenWrt](https://radio.freifunk.net/2023/06/13/mesh-in-ap-mode/)

## Other Related Links

A diverse collection of interesting posts/articles/papers/videos.

* "Understanding Mesh Networking", [Part I](https://web.archive.org/web/20230629104052/https://www.inthemesh.com/archive/understanding-mesh-networking-part-i/) [Part II](https://web.archive.org/web/20230629104052/https://inthemesh.com/archive/understanding-mesh-networking-part-ii/)
* [The world in which IPv6 was a good design](https://apenwarr.ca/log/20170810)
* [Scalability of Mobile Ad Hoc Networks: Theory vs Practice](http://dx.doi.org/10.1109/MILCOM.2010.5680385)
* "The Scalability of Mesh Networks" [Part I](https://web.archive.org/web/20230629104052/https://inthemesh.com/archive/the-scalability-of-mesh-networks-part-ii/) [Part II](https://inthemesh.com/archive/the-scalability-of-mesh-networks-part-ii/)
* [B.A.T.M.A.N. - Better Approach to Mobile Ad-Hoc Networking](https://media.ccc.de/v/cccamp07-en-2039-BATMAN_-_Better_Approach_to_Mobile_Ad-Hoc_Networking)
* [LightKone](https://www.lightkone.eu): abstract mesh routing protocol via 5 parameters
* [APuP](https://blog.freifunk.net/2024/08/24/a-new-way-to-mesh-apup/)
