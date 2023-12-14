# Ratelimit 3

Similar to ratelimit-2.

* Change RREQ packet to accumalates multiple requests and send them at most once per second



* Add PING/PONG packets to detect dead neighbors.

If we send a packet and do not receive a packet back after one second (for us or not),
then we send a PING packet up to three times until we declare a neighbor lost after three seconds.

* Add RERR packet to report if a node is not reachable anymore.

If we get a DATA packet and do not have a next hop, then we drop it and
send a UNREACHABLE back the path until the orignal source is reached or
the receiving node does not know a route that would the destination towards that goal. (?)
