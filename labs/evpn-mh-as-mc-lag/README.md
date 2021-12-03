![plot](Fig13_evpn_mh.PNG)

# VNI versus EVI

As defined in [RFC8365](https://datatracker.ietf.org/doc/html/rfc8365) and (also) illustrated by Juniper [here](https://www.juniper.net/documentation/us/en/software/junos/evpn-vxlan/topics/concept/vxlan-evpn-integration-overview.html) under "VNI Aware Service Use Case", a VxLAN Network Identifier (VNI) is not the same thing as an [EVPN Instance (EVI)](https://datatracker.ietf.org/doc/html/rfc7432#section-3).


## VxLAN Network Identifier (VNI)
A VxLAN Network Identifier (VNI) is a 24-bit label that is used as part of UDP encapsulation: A data plane identifier to distinguish between different services, for example traffic from different customers or different applications. It can be viewed as an extension of the 12-bit VLAN concept.

## EVPN Instance (EVI)
An EVPN Instance is a 16-bit value used to identify unique EVPN services inside a given network.

## Virtual Identifier to EVI mapping
12-bit VLANs and their 24-bit overlay cousins VNIs [can be mapped](https://datatracker.ietf.org/doc/html/rfc8365#section-5.1.2) to 16-bit EVIs in 2 distinct ways:
1. 1:1 Single broadcast domain (e.g. subnet) <-> unique EVI
2. n:1 Multiple broadcast domains -> single EVI

In the former case, it is possible to [auto-derive](https://datatracker.ietf.org/doc/html/rfc8365#section-5.1.2.1) EVPN RD and RT values as \<router-id\>:VNI and \<2-byte-AS\>:VNI respectively.

In SR Linux, the EVI and VNI for a service are provisioned separately (under the mac-vrf instance and the VxLAN tunnel-interface respectively). Cumulus only provisions the VNI and assume the EVI is the same (implicitly limiting usable VXLAN ID space to 16 bits for auto-rd/rt). Since we cannot provision the EVI, interop requirements force us to configure VNI==EVI.

# Verification

## Leaf1a (CVX)
```
root@leaf1a:mgmt:~# net show bgp l2vpn evpn es-evi
Flags: L local, R remote, I inconsistent
VTEP-Flags: E EAD-per-ES, V EAD-per-EVI
VNI      ESI                            Flags VTEPs
10       03:44:38:39:be:ef:aa:00:00:01  LR    1.1.0.2(EV)
10       03:44:38:39:be:ef:aa:00:00:02  LR    1.1.0.2(EV) 
```

## Leaf1b (SRL):
```
A:leaf-1b-1.1.0.2# /show system network-instance ethernet-segments                                                                                                                                                 
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ES-leaf1-leaf2.CE1 is up, all-active
  ESI      : 03:44:38:39:be:ef:aa:00:00:01
  Alg      : default
  Peers    : 1.1.0.1
  Interface: lag1
  Network-instances:
     Blue-MAC-VRF-10
      Candidates : 1.1.0.1 (DF), 1.1.0.2
      Interface : lag1.0
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ES-leaf1-leaf2.Spines is up, all-active
  ESI      : 03:44:38:39:be:ef:aa:00:00:02
  Alg      : default
  Peers    : 1.1.0.1
  Interface: lag2
  Network-instances:
     Blue-MAC-VRF-10
      Candidates : 1.1.0.1 (DF), 1.1.0.2
      Interface : lag2.0
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Summary
 2 Ethernet Segments Up
 0 Ethernet Segments Down
```
