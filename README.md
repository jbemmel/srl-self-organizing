# srl-self-organizing
Each node has the exact same config, and configures itself based on LLDP

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


## Install
`git clone https://github.com/jbemmel/srl-self-organizing.git /etc/opt/srlinux/appmgr`
