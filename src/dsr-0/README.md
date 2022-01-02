# Dynamic Source Routing

A simplistic implementation of Dynamic Source Routing (DSR). It is a reactive protocol that includes the entire path in the packet header. A description of the algorithm can be found [here](https://www3.cs.stonybrook.edu/~samir/cse590/routing.pdf) and a complete specification is defined in [RFC4728](https://datatracker.ietf.org/doc/html/rfc4728). But note that the code here is a very basic implementation of the algorithm only.

Used are Route Request (RREQ) and Route Reply (RREP) packets. RREQs are always send as broadcast and record the address in the packet. When a RREQ is received by a target, a RREP is send as response to the source and carries the path back. The path consists of MAC/IP addresses. Also, the path might get updated on the way back since sending and receiving address might not be interchangeable. Route Error (RERR) packets are not implemented. Also routes are not cached by intermediate nodes.

Pro:
- nodes have no state
  - except sequence numbers, but those have no effect if lost

Cons:
- overhead for all the paths in the packet headers
- hardware addresses (MAC) might be exposed
