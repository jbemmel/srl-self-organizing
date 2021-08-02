# srl-self-organizing

What if network nodes would auto-configure themselves?

This basic example offers a starting point for a Python-based SR Linux agent that configures the local node.
Each node has a generic config, and is configured with peering links and eBGP related parameters based on LLDP

What is demonstrated:
* How to [create a custom agent for SR Linux](https://github.com/jbemmel/srl-self-organizing/tree/main/appmgr)
* How to [register to receive LLDP events](https://github.com/jbemmel/srl-self-organizing/blob/main/appmgr/auto-config-agent.py#L47)
* How to [use gnmic to send JSON configuration to the local node](https://github.com/jbemmel/srl-self-organizing/blob/main/appmgr/gnmic-configure-interface.sh) ( note: just as a Proof-of-Concept )
* How to [build a custom Docker container](https://github.com/jbemmel/srl-self-organizing/tree/main/Docker) containing the sources

2 roles currently supported: Spine or Leaf
* All LLDP neighbors advertise the same port -> rank == port (starting from ethernet-1/1 = Leaf/Spine 1, etc)
* Could auto-determine role: Some links connected but no LLDP or MAC address instead of SRL port name -> assume this is a leaf node, otherwise spine
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
1. Checkout and build the base image from https://github.com/jbemmel/srl-baseimage
2. Checkout the project from git
3. `cd Docker && make build` -> this creates a local Docker image called 'srl/auto-config'
4. `sudo clab deploy -t ./srl-leafspine.lab`

## Networking design details
This example uses OSPFv3 to exchange loopback routes within the fabric, iBGP v4/v6 towards Linux hosts and iBGP EVPN between leaves and spine route-reflectors
* Spines share a private base AS, each leaf gets a unique leaf AS (though currently not used)
* Interfaces use /31 IPv4 link addresses (required for VXLAN v4), OSPFv3 uses IPv6 link-local addresses (TODO link-local with BGP unnumbered)
* Spine side uses dynamic neighbors, such that the spines only need to know a subnet prefix for leaves
* Routing policy to only import/export loopback IPs
* Global AS set to unique leaf AS, could also use single global AS such that EVPN auto route-targets would work

## EVPN overlay
The [SR Linux EVPN User guide](https://documentation.nokia.com/cgi-bin/dbaccessfilename.cgi/3HE16831AAAATQZZA01_V1_SR%20Linux%20R21.3%20EVPN-VXLAN%20User%20Guide.pdf) describes how to setup EVPN overlay services. The agent auto-configures spines to be iBGP route reflectors for EVPN, and illustrates how VLAN interfaces can automatically be added based on (for example) Kubernetes container startup events.

## Using LLDP for signalling topology changes
To auto-configure LAGs, upon receiving an LLDP event the agent temporarily modifies the system name:
1. LLDP Port ethernet/1-1: h1 event received
2. Leaf1 modifies its system name: \<system ID\>-1-h1 (e.g. "1.1.1.1-1-h1")
3. Spine1 receives this and - being a spine - modifies its system name in response, to the same string
4. Leaf1 and Leaf2 both receive this change through LLDP
   + Leaf1, recognizing its own system ID, restores its hostname to the regular value (which triggers another update)
   + Leaf2, recognizing that the update comes from its peer via the spine layer, updates its internal state to record 'h1'
5. Spine1 upon receiving the restored hostname via LLDP, resets its hostname

According to the standard, LLDP messages are sent out every 30 seconds, and SR Linux uses whatever is configured as a hostname at the transmission interval. This implies the need for an ACK-based protocol where the spine only updates its hostname after having received confirmation that its previous change was received.
