# srl-self-organizing

What if network nodes would auto-configure themselves?

This basic example offers a starting point for a Python-based SR Linux agent that configures the local node.
All nodes can share a single generic global config file, and each agent configures peering links, IGP related parameters and EVPN overlay/LAG based on LLDP events.

What is demonstrated:
* How to [create a custom agent for SR Linux](https://github.com/jbemmel/srl-self-organizing/tree/main/src/auto-config-agent)
* How to [register to receive LLDP events](https://github.com/jbemmel/srl-self-organizing/blob/main/src/auto-config-agent/auto-config-agent.py#L57)
* How to [use gnmic to send JSON configuration to the local node](https://github.com/jbemmel/srl-self-organizing/blob/main/src/auto-config-agent/scripts/gnmic-configure-interface.sh) ( note: just as a Proof-of-Concept )
* How to [use Python (pygnmic) to change configuration](https://github.com/jbemmel/srl-self-organizing/blob/main/src/auto-config-agent/auto-config-agent.py#L458)
* How to [build a custom Docker container](https://github.com/jbemmel/srl-self-organizing/tree/main/Docker) containing the sources

3 roles currently supported, as inferred from the hostname: (super)spine or leaf
* Role and rank derived from hostname if possible ( "leaf1" -> role=leaf rank=1 )
* If not: All LLDP neighbors advertise the same port -> rank == port (starting from ethernet-1/1 = Leaf/Spine 1, etc)
* Could auto-determine role: Some links connected but no LLDP or MAC address instead of SRL port name -> assume this is a leaf node, otherwise spine

YANG model (included in single initial config) provides parameters:
* AS base: Superspine EBGP AS number, each Leaf gets <base + 1 + rank>
* Link prefix: IP/mask to use for generating peer-2-peer /31 link addresses 
  ( For example: 192.168.0.0/24, spine1=192.168.0.0/31 and leaf1=192.168.0.1/31 )
* Loopback prefix: IP/mask for generating loopbacks
  ( For example: 1.1.0.0/23, spine1=1.1.0.1 and leaf1=1.1.1.1 )
* Max number of spines/leaves/hosts-per-leaf in the topology
* Whether to enable EVPN, and what model (symmetric/asymmetric IRB)
* Whether to enable EVPN based auto provisioning of MC-LAGs (default: true)
* Whether to use OSPFv3, ISIS, regular BGPv4 or BGP Unnumbered

## Deploy lab
```
# Checkout the project from git:
git clone --recurse-submodules https://github.com/jbemmel/srl-self-organizing.git
cd srl-self-organizing
make -C ./Docker all # -> this creates a local Docker image called 'srl/auto-config'

sudo containerlab deploy -t ./srl-leafspine.lab # -> this creates a lab with 4 leaves and various MC-LAG variations
```

## Networking design details
This example uses:
* Either OSPFv3, ISIS, BGPv4 or BGP unnumbered to exchange loopback routes within the fabric, 
* (optional) eBGP v4/v6 towards Linux hosts
* iBGP EVPN between leaves and (super)spine route-reflector(s), with VXLAN overlay
* (super)spines share a private base AS for EBGP, each leaf gets a unique leaf AS
* Interfaces use /31 IPv4 link addresses or IPv6 unnumbered, OSPFv3 uses IPv6 link-local addresses
* (Super)spine side uses dynamic neighbors, such that the spines only need to know a subnet prefix for leaves
* Routing policy to only import/export loopback IPs
* Global AS set to overlay AS, such that EVPN auto route-targets work; not added to EBGP routes
* Superspines remove AS path received from spines, such that other spines don't reject these routes
* Host subnet size is configurable, default /31 (but some hosts may not support that)
* [NEW] EVPN auto LAG discovery based on LLDP and either Large Communities (RFC8092) or IPv6-encoding

## EVPN overlay
The [SR Linux EVPN User guide](https://documentation.nokia.com/cgi-bin/dbaccessfilename.cgi/3HE16831AAAATQZZA01_V1_SR%20Linux%20R21.3%20EVPN-VXLAN%20User%20Guide.pdf) describes how to setup EVPN overlay services. The agent auto-configures spines to be iBGP route reflectors for EVPN.

The agent supports both *asymmetric* and *symmetric* IRB configuration models, and will annotate the configuration to highlight the difference.
One can use 
```
info from state /platform linecard 1 forwarding-complex 0 datapath
```
to explore differences in resource usage and scaling.

## EVPN based signalling for MultiHoming LAGs
The agent listens for LLDP events from the SR Linux NDK, and populates a BGP Community set with encoded port and MAC information for each neighbor.
It then configures a special control-plane-only IP VRF with a loopback ( == router ID ) to announce an RT5 IP Prefix route with the LLDP information.
By listening for route count changes, each agent detects changes in LLDP communities (or IPv6 host routes with encoded LLDP data), and updates its local MH configuration (Ethernet Segments with ESI).

Optionally, the agent could stop listening once all links are discovered, and/or one could disable BGP for the IP VRF. For this demo, the agent simply keeps listening indefinitely.

Sample annotated configuration snippets:
```
A:leaf-1-1.1.1.1# /system network-instance                                                                                                                                                                         
--{ + running }--[ system network-instance ]--                                                                                                                                                                     
A:leaf-1-1.1.1.1# info                                                                                                                                                                                             
    protocols {
        evpn {
            ethernet-segments {
                bgp-instance 1 {
                    ethernet-segment mc-lag3 {
                        admin-state enable
                        esi 00:12:12:12:12:12:12:00:00:03 !!! EVPN MC-LAG with [('1.1.1.2', '3')]
                        interface lag3
                        multi-homing-mode all-active
                    }
                    ethernet-segment mc-lag4 {
                        admin-state enable
                        esi 00:12:12:12:12:12:12:00:00:04 !!! EVPN MC-LAG with [('1.1.1.2', '4'), ('1.1.1.3', '4'), ('1.1.1.4', '4')]
                        interface lag4
                        multi-homing-mode all-active
                    }
                }
            }
        }
        bgp-vpn {
            bgp-instance 1 {
            }
        }
    }
```

```
A:leaf-1-1.1.1.1# /interface irb0                                                                                                                                                                                  
--{ + running }--[ interface irb0 ]--                                                                                                                                                                              
A:leaf-1-1.1.1.1# info                                                                                                                                                                                             
    admin-state enable
    subinterface 3 {
        admin-state enable
        ipv4 {
            address 192.168.127.9/30 {
                primary
            }
            arp {
                learn-unsolicited true !!! To support MC-LAG, see https://documentation.nokia.com/cgi-bin/dbaccessfilename.cgi/3HE16831AAAATQZZA01_V1_SR%20Linux%20R21.3%20EVPN-VXLAN%20User%20Guide.pdf p72
                evpn {
                    advertise dynamic {
                        !!! for ARP synchronization across MH leaf nodes
                    }
                }
            }
        }
        ipv6 {
        }
        anycast-gw {
        }
    }
```

## Superspine support
Adding superspine support required some changes to the auto-configuration logic. Router IDs are now numbered starting with 0 at the leaves ( e.g. Leaf1=1.1.0.1 )
because the local agent does not know whether a superspine will be included in the topology or not.

The node role and rank are now derived from the hostname; in a 3-tier topology leaf nodes cannot easily determine their rank based on the spine port(s) they're connected to.
Deriving things from the hostname also allows a single config file to be used across the entire fabric.

## Using LLDP for signalling topology changes (deprecated)
To auto-configure LAGs, upon receiving an LLDP event the agent temporarily modifies the system name:
1. LLDP Port ethernet/1-1: h1 event received
2. Leaf1 modifies its system name: \<system ID\>-1-h1 (e.g. "1.1.1.1-1-h1")
3. Spine1 receives this and - being a spine - modifies its system name in response, to the same string
4. Leaf1 and Leaf2 both receive this change through LLDP
   + Leaf1, recognizing its own system ID, restores its hostname to the regular value (which triggers another update)
   + Leaf2, recognizing that the update comes from its peer via the spine layer, updates its internal state to record 'h1'
5. Spine1 upon receiving the restored hostname via LLDP, resets its hostname

According to the standard, LLDP messages are sent out every 30 seconds, and SR Linux uses whatever is configured as a hostname at the transmission interval. This implies the need for an ACK-based protocol where the spine only updates its hostname after having received confirmation that its previous change was received.
