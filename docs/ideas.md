# Ideas

There are several desirable properties of mesh routing protocols:

- usable also in huge sized networks
  - reachability of a node increases:
    - if a nodes address is in the hirarchy of the neighbors
    - if a node is involved in a lot of traffic
    - if a node stays in the same place for a long time
  - => make the reach of a node finite, so that an oversized network won't get killed by routing overhead
- no overhead when there is no traffic, important for wireless networks
  - wireless networks is a pricious resource that must not be overutilized
  - => reactiv protocols, they approach the state of proactive protocols anyway
- efficient flooding
  - wireless networks is a pricious resource that must not be overutilized
  - => use OLSRs Multi Point Relay (MPR) or even better the goTennas "critical node" approach
- good path selection
  - practice has shown that a bandwidth metric is the most suitable for real world use
- use timing information
  - agree on individual send/receive times to support very low powered devices
- hard to interfere by malicious peers
  - prevent resource exhaustion (e.g. broadcast storms) / DDOS attacks
  - prevent traffic to be intentionally dropped / blackholed
- incentive for nodes to participate
  => a nodes that forwards traffic gets it's own traffic forwarded with priority
- dynamic link aggregation
- use multiple routes to offload traffic
  - usually it is good to send packet of one connection context on one route to preserve the packet order