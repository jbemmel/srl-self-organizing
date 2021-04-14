# srl-self-organizing

What if network nodes would auto-configure themselves?

This basic example offers a starting point for a Python-based SR Linux agent that configures the local node.
Each node has a generic config, and is configured with peering links and eBGP based on LLDP

What is demonstrated:
* How to [create a custom agent for SR Linux](https://github.com/jbemmel/srl-self-organizing/tree/main/appmgr)
* How to [register to receive LLDP events](https://github.com/jbemmel/srl-self-organizing/blob/main/appmgr/auto-config-agent.py#L47)
* How to [use gnmic to send JSON configuration to the local node](https://github.com/jbemmel/srl-self-organizing/blob/main/appmgr/gnmic-configure-interface.sh) ( note: just as a Proof-of-Concept )
* How to [build a custom Docker container](https://github.com/jbemmel/srl-self-organizing/tree/main/Docker) containing the sources

2 roles currently supported: Spine or Leaf
* All LLDP neighbors advertise the same port -> rank == port (starting from ethernet-1/1 = Leaf/Spine 1, etc)
* Could auto-determine role: Some links connected but no LLDP -> assume this is a leaf node, otherwise spine
* For now: role is an agent parameter

YANG model provides parameters:
* role: leaf|spine|superspine
* AS base: Spine AS number, each Leaf gets <base + rank>
* Link prefix: IP/mask to use for generating peer-2-peer /31 link addresses 
  ( For example: 192.168.0.0/24, spine1=192.168.0.0/31 and leaf1=192.168.0.1/31 )
* Loopback prefix: IP/mask for generating loopbacks
  ( For example: 1.1.0.0/23, spine1=1.1.0.1 and leaf1=1.1.1.1 )
* Max number of spines/leaves in the topology

## Deploy lab
1. Checkout the project from git
2. `cd Docker && make build` -> this creates a local Docker image called 'srl/auto-config'
3. `sudo clab deploy -t ./srl-son.lab`

## eBGP design details
This example uses only eBGP peering to exchange routes
* Spines share a private base AS, each leaf gets a unique leaf AS
* eBGP peering using /31 IPv4 link addresses
* Spine side uses dynamic neighbors, such that the spines only need to known a subnet prefix for leaves
* Routing policy to 
  + stop forwarding leaf loopbacks beyond the spines (tag with no-export)
  + only advertise direct attached subnets (don't export AS path length >= 1 routes)
  + not advertise /31 peering links 
