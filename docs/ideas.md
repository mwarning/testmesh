# Ideas

There are several desirable properties of mesh routing protocols:

- usable also in huge sized networks
  - => make the reach of a node finite, so that an oversized network won't get killed by routing overhead
- no overhead when there is no traffic, important for wireless networks
  - wireless networks is a pricious resource that must not be overutilized
  - => reactiv protocols, they approach the state of proactive protocols anyway
- efficient flooding
  - wireless networks is a pricious resource that must not be overutilized
  - => use OLSRs Multi Point Relay (MPR) or even better the goTenna approach
- good path selection
  - practice has shown that a bandwidth metric is the most suitable for real world use
- use timing information
  - agree on individual send/receive times to support very low powered devices
