# Ratelimit 0

Main idea: Hard limit amount of broadcast traffic.

Packets:
- Route Request (RREQ)
- Route Response (RREP)
- Data Packet (DATA)

- reactive
- only broadcast packets are for Route Request
- only send/forward broadcasts as
  - maximum of x percent of the total traffic rate
  - minimum of y packets per second
- dynamic route timeout is the time the node has been online
  - plus a hard-coded global min/max timeout
- route over layer-2 a preferred over layer-3
  - assumption is that layer-3 is over cable, layer-2 over WLAN
