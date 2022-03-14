# AODV 0

A simple implementation of the Ad-hoc On Demand Distance Vector routing protocol algorithm. A complete protocol specicification can be found in [RFC 3561](https://datatracker.ietf.org/doc/html/rfc3561).
This is reactive algorithm that is also used for the Zigbee.

There are Route Request (RREQ) packets that are broadcasted to find a destination. A Route Response (RREP) packet is then send back as a unicast to the source of the Route Request.
