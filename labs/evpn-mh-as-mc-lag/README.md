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

In the former case, it is possible to auto-derive EVPN RD and RT values as follows:
