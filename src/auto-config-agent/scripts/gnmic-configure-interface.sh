#!/bin/bash

# Sample script to provision SRLinux using gnmic
# TODO next version: Use Jinja2 templates plus native Python logic instead
#
#
ROLE="$1"  # "spine" or "leaf" or "endpoint"
INTF="$2"
IP_PREFIX="$3"
PEER="$4"         # 'host' for Linux nodes and endpoints
PEER_IP="$5"
AS="$6"
ROUTER_ID="$7"
PEER_AS_MIN="$8"     # Overlay AS in case of leaf-host
PEER_AS_MAX="$9"     # Host AS in case of leaf-host
LINK_PREFIX="${10}"  # IP subnet used for allocation of IPs to BGP peers
PEER_TYPE="${11}"
PEER_ROUTER_ID="${12}"
OSPF_ADMIN_STATE="${13}" # 'enable' or 'disable'
USE_EVPN_OVERLAY="${14}" # '1' or '0'

GNMIC="/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf"

temp_file=$(mktemp --suffix=.json)
exitcode=0

# Set loopback IP, if provided
if [[ "$ROUTER_ID" != "" ]]; then

if [[ "$ROLE" == "leaf" ]]; then
# XXX cannot ping system0 interface, may want to create lo0.0 with ipv6 addr
LOOPBACK_IF="system"
else
LOOPBACK_IF="lo"
fi

cat > $temp_file << EOF
{
  "admin-state": "enable",
  "subinterface": [
    {
      "index": 0,
      "admin-state": "enable",
      "ipv4": { "address": [ { "ip-prefix": "$ROUTER_ID/32" } ] },
      "ipv6": { "address": [ { "ip-prefix": "2001::${ROUTER_ID//\./:}/128" } ] }
    }
  ]
}
EOF
$GNMIC set --replace-path /interface[name=${LOOPBACK_IF}0] --replace-file $temp_file
exitcode+=$?

$GNMIC set --update /network-instance[name=default]/interface[name=${LOOPBACK_IF}0.0]:::string:::''
exitcode+=$?

# Use ipv6 link local addresses to advertise ipv4 VXLAN system ifs via OSPFv3
# Still requires static (link local) IPv4 addresses on each interface
if [[ "$OSPF_ADMIN_STATE" == "enable" ]]; then
cat > $temp_file << EOF
{
  "router-id": "$ROUTER_ID",
  "admin-state": "enable",
  "version": "ospf-v3",
  "address-family": "ipv4-unicast",
  "max-ecmp-paths": 8,
  "area": [
    {
      "area-id": "0.0.0.0",
      "interface": [
        {
          "admin-state": "enable",
          "interface-name": "${LOOPBACK_IF}0.0",
          "passive": true
        }
      ]
    }
  ]
}
EOF
$GNMIC set --update-path /network-instance[name=default]/protocols/ospf/instance[name=main] --update-file $temp_file
exitcode+=$?
fi

# Need a generic BGP policy to advertise loopbacks; apply specifically
cat > $temp_file << EOF
{
  "prefix-set": [
    {
      "name": "loopbacks",
      "prefix": [
        { "ip-prefix": "0.0.0.0/0","mask-length-range": "32..32" },
        { "ip-prefix": "::/0", "mask-length-range": "128..128" }
      ]
    }
  ],
  "policy": [
    {
      "name": "select-loopbacks",
      "default-action": { "reject": { } },
      "statement": [
        {
          "sequence-id": 10,
          "match": {
            "prefix-set": "loopbacks"
          },
          "action": { "accept": { } }
        }
      ]
    },
    {
      "name": "reject-local-routes",
      "default-action": { "accept": { } },
      "statement": [
        {
          "sequence-id": 10,
          "match": {
            "protocol": "srl_nokia-common:local"
          },
          "action": { "reject": { } }
        }
      ]
    }
  ]
}
EOF

# Or replace to reset all to a known state?
$GNMIC set --update-path /routing-policy --update-file $temp_file
exitcode+=$?

if [[ "$ROLE" == "spine" ]]; then

if [[ "$OSPF_ADMIN_STATE" == "disable" ]]; then
IFS='' read -r -d '' EBGP_NEIGHBORS << EOF
{
  "prefix": "$LINK_PREFIX",
  "peer-group": "leaves",
  "allowed-peer-as": [
    "$PEER_AS_MIN..$PEER_AS_MAX"
  ]
},
EOF
fi

if [[ "$USE_EVPN_OVERLAY" == "1" ]]; then
IFS='' read -r -d '' EVPN_SPINE_GROUP << EOF
,
{
  "group-name": "evpn",
  "admin-state": "enable",
  "peer-as": $AS,
  "evpn": { "admin-state": "enable" },
  "ipv4-unicast": { "admin-state": "disable" },
  "ipv6-unicast": { "admin-state": "disable" },
  "route-reflector": {
    "client": true,
    "cluster-id": "$ROUTER_ID"
  }
}
EOF
fi

if [[ "$OSPF_ADMIN_STATE" == "disable" ]]; then
IFS='' read -r -d '' BGP_LEAVES_GROUP << EOF
,
{
  "group-name": "leaves",
  "admin-state": "enable",
  "import-policy": "select-loopbacks",
  "export-policy": "select-loopbacks"
}
EOF
fi

IFS=. read ip1 ip2 ip3 ip4 <<< "$ROUTER_ID"

IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"dynamic-neighbors": {
    "accept": {
      "match": [
        $EBGP_NEIGHBORS
        {
          "prefix": "$ip1.$ip2.$ip3.0/22",
          "peer-group": "evpn",
          "allowed-peer-as": [ "$AS" ]
        }
      ]
    }
},
"failure-detection": { "enable-bfd" : true, "fast-failover" : true },
"evpn": { "rapid-update": true },
"group": [
    {
      "group-name": "fellow-spines",
      "admin-state": "enable",
      "peer-as": $AS
    }
    ${BGP_LEAVES_GROUP}
    ${EVPN_SPINE_GROUP}
  ],
EOF
elif [[ "$ROLE" == "leaf" ]]; then

IFS='' read -r -d '' HOSTS_GROUP << EOF
{
  "group-name": "hosts",
  "admin-state": "enable",
  "ipv6-unicast" : { "admin-state" : "enable" },
  "peer-as": $PEER_AS_MAX,
  "local-as": [ { "as-number": $PEER_AS_MIN } ],
  "send-default-route": {
    "ipv4-unicast": true,
    "ipv6-unicast": true
  },
  "export-policy": "overlay-export-as-to-community"
}
EOF

IFS='' read -r -d '' DYNAMIC_HOST_PEERING << EOF
"dynamic-neighbors": {
    "accept": {
      "match": [
        {
          "prefix": "$LINK_PREFIX",
          "peer-group": "hosts",
          "allowed-peer-as": [
            "$PEER_AS_MAX"
          ]
        }
      ]
    }
}
EOF

if [[ "$USE_EVPN_OVERLAY" == "1" ]]; then
DEFAULT_HOSTS_GROUP=""
DEFAULT_DYNAMIC_HOST_PEERING=""
IFS='' read -r -d '' EVPN_RR_GROUP << EOF
{
  "group-name": "evpn-rr",
  "admin-state": "enable",
  "export-policy": "reject-local-routes",
  "peer-as": $PEER_AS_MIN,
  "local-as": [ { "as-number": $PEER_AS_MIN } ],
  "evpn": { "admin-state": "enable" },
  "transport" : { "local-address" : "${ROUTER_ID}" }
}
EOF

else
DEFAULT_HOSTS_GROUP="$HOSTS_GROUP"
DEFAULT_DYNAMIC_HOST_PEERING="$DYNAMIC_HOST_PEERING,"
EVPN_RR_GROUP=""
fi

IFS='' read -r -d '' BGP_IP_UNDERLAY << EOF
"ipv4-unicast": {
  "admin-state": "enable",
  "multipath": {
    "max-paths-level-1": 8,
    "max-paths-level-2": 8
  }
},
"ipv6-unicast": {
  "admin-state": "enable",
  "multipath": {
    "max-paths-level-1": 8,
    "max-paths-level-2": 8
  }
},
EOF

if [[ "$OSPF_ADMIN_STATE" == "disable" ]]; then
IFS='' read -r -d '' SPINES_GROUP << EOF
{
  "group-name": "spines",
  "admin-state": "enable",
  "import-policy": "select-loopbacks",
  "export-policy": "select-loopbacks",
  "failure-detection": { "enable-bfd" : true, "fast-failover" : true },
  "peer-as": $PEER_AS_MIN,
  "local-as": [ { "as-number": $AS } ]
}
EOF
else
BGP_IP_UNDERLAY=""
fi

if [[ "$DEFAULT_HOSTS_GROUP" != "" ]] && [[ "$SPINES_GROUP" != "" ]]; then
SPINES_GROUP=",$SPINES_GROUP"
fi
if [[ "$SPINES_GROUP" != "" ]] && [[ "$EVPN_RR_GROUP" != "" ]]; then
EVPN_RR_GROUP=",$EVPN_RR_GROUP"
fi

IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"evpn": { "rapid-update": true },
"preference": {
 "ibgp": 171, "_annotate_ibgp": "Lower than BGP routes received from hosts" },
$DEFAULT_DYNAMIC_HOST_PEERING
"group": [
    $DEFAULT_HOSTS_GROUP
    $SPINES_GROUP
    $EVPN_RR_GROUP
],
EOF
else
IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"group": [
    {
      "group-name": "leaf-ibgp",
      "admin-state": "enable",
      "export-policy": "select-loopbacks",
      "ipv6-unicast" : { "admin-state" : "enable" },
      "peer-as": $PEER_AS_MIN
    }
],
EOF
fi

#
# By default, the global AS and local AS get prepended to all routes sent out
# Set lower preference for ibgp routes via EVPN
#
cat > $temp_file << EOF
{
  "admin-state": "enable",
  "autonomous-system": $AS,
  "router-id": "$ROUTER_ID", "_annotate_router-id": "${ROUTER_ID##*.}",
  $DYNAMIC_NEIGHBORS
  $BGP_IP_UNDERLAY
  "route-advertisement": {
    "rapid-withdrawal": true
  }
}

EOF

$GNMIC set --update-path /network-instance[name=default]/protocols/bgp --update-file $temp_file
exitcode+=$?

# Annotate /system as well
cat > $temp_file << EOF
{ "_annotate" : "${ROUTER_ID##*.}" }
EOF

$GNMIC set --update-path /system --update-file $temp_file
exitcode+=$?

# For leaves, create VXLAN tunnel interface vxlan0 for overlay VRF
if [[ "$ROLE" == "leaf" ]] && [[ "$USE_EVPN_OVERLAY" == "1" ]]; then

cat > $temp_file << EOF
{
  "vxlan-interface": [
    {
      "index": 0,
      "type": "srl_nokia-interfaces:routed",
      "ingress": {
        "vni": 10000
      },
      "egress": {
        "source-ip": "use-system-ipv4-address"
      }
    }
  ]
}
EOF
$GNMIC set --update-path /tunnel-interface[name=vxlan0] --update-file $temp_file
exitcode+=$?

# Create a sample BGP policy to convert customer AS to ext community (origin)
cat > $temp_file << EOF
{
  "as-path-set": [ { "name": "CUSTOMER1", "expression": "${PEER_AS_MAX}" } ],
  "community-set": [ { "name": "CUSTOMER1", "member": [ "origin:${PEER_AS_MAX}:0" ] } ],
  "policy": [
    {
      "name": "overlay-export-as-to-community",
      "statement": [
        {
          "sequence-id": 10,
          "match": { "bgp": { "as-path-set": "CUSTOMER1" } },
          "action": { "accept": { "bgp": { "communities": { "add": "CUSTOMER1" } } } }
        }
      ]
    }
  ]
}
EOF

$GNMIC set --update-path /routing-policy --update-file $temp_file
exitcode+=$?

# Configure lo0.0 with special loopback IP to advertise communities
cat > $temp_file << EOF
{
  "admin-state": "enable",
  "subinterface": [
    {
      "index": 0,
      "admin-state": "enable",
      "ipv4": { "address": [ { "ip-prefix": "192.0.2.0/32" } ] },
      "ipv6": { "address": [ { "ip-prefix": "2001:db8::192:0:2:0/128" } ] }
    }
  ]
}
EOF
$GNMIC set --replace-path /interface[name=lo0] --replace-file $temp_file
exitcode+=$?

# Set autonomous system & router-id for BGP to hosts
# Assumes a L3 service
cat > $temp_file << EOF
{
    "type": "srl_nokia-network-instance:ip-vrf",
    "_annotate_type": "routed",
    "admin-state": "enable",
    "interface": [ { "name": "lo0.0" } ],
    "vxlan-interface": [ { "name": "vxlan0.0" } ],
    "protocols": {
      "bgp": {
        "admin-state": "enable",
        "autonomous-system": $PEER_AS_MIN,
        "router-id": "$ROUTER_ID", "_annotate_router-id": "${ROUTER_ID##*.}",
        "ipv4-unicast": {
          "admin-state": "enable",
          "multipath": {
            "max-paths-level-1": 32,
            "max-paths-level-2": 32
          }
        },
        "ipv6-unicast": {
          "admin-state": "enable",
          "multipath": {
            "max-paths-level-1": 32,
            "max-paths-level-2": 32
          }
        },
        $DYNAMIC_HOST_PEERING,
        "group" : [ $HOSTS_GROUP ],
        "route-advertisement": {
          "rapid-withdrawal": true
        },
        "ebgp-default-policy": {
          "import-reject-all": false,
          "export-reject-all": false
        }
      },
      "bgp-evpn": {
        "bgp-instance": [
          {
            "id": 1,
            "admin-state": "enable",
            "vxlan-interface": "vxlan0.0",
            "evi": 10000,
            "ecmp": 8
          }
        ]
      },
      "bgp-vpn": {
        "bgp-instance": [
          {
            "id": 1,
            "route-target": {
              "export-rt": "target:$PEER_AS_MIN:10000",
              "import-rt": "target:$PEER_AS_MIN:10000"
            }
          }
        ]
      }
    }
  }
EOF
$GNMIC set --update-path /network-instance[name=overlay] --update-file $temp_file
exitcode+=$?

fi # leaf with EVPN enabled

fi # if router_id provided, first time only

if [[ "$PEER_TYPE" != "host" ]] && [[ "$ROLE" != "endpoint" ]]; then
  _ROUTED='"type" : "routed",'
fi
if [[ "$PEER_TYPE" == "host" ]] || [[ "$ROLE" == "endpoint" ]]; then
  _VLAN_TAGGING='"vlan-tagging" : true,'
  _VLAN='"srl_nokia-interfaces-vlans:vlan": { "encap": { "single-tagged": { "vlan-id": 1 } } },'
fi
if [[ "${IP_PREFIX}" != "" ]]; then
_IP127="${IP_PREFIX//\/31/\/127}"
IFS='' read -r -d '' _IP_ADDRESSING << EOF
,"ipv4": { "address": [ { "ip-prefix": "$IP_PREFIX" } ] },
 "ipv6": { "address": [ { "ip-prefix": "2001::${_IP127//\./:}" } ] }
EOF
else
# Enable IPv4+IPv6 but don't put addresses (yet)
IFS='' read -r -d '' _IP_ADDRESSING << EOF
,"ipv4": {  },
 "ipv6": {  }
EOF
fi

cat > $temp_file << EOF
{
  "description": "To $PEER",
  $_VLAN_TAGGING
  "admin-state": "enable",
  "subinterface": [
    {
      "index": 0,
      $_ROUTED
      $_VLAN
      "admin-state": "enable"
      $_IP_ADDRESSING
    }
  ]
}
EOF

# Update interface IP address
$GNMIC set --replace-path /interface[name=$INTF] --replace-file $temp_file
exitcode+=$?

# Add it to the correct instance
if [[ "$ROLE" == "leaf" ]] && [[ "$PEER_TYPE" == "host" ]] && [[ "$USE_EVPN_OVERLAY" == "1" ]]; then
VRF="overlay"
else
VRF="default"
fi
$GNMIC set --update /network-instance[name=$VRF]/interface[name=${INTF}.0]:::string:::''
exitcode+=$?

# Add it to OSPF (if enabled)
# Note: To view: info from state /bfd
if [[ "$PEER_TYPE" != "host" ]] && [[ "$ROLE" != "endpoint" ]]; then

if [[ "$OSPF_ADMIN_STATE" == "enable" ]]; then
cat > $temp_file << EOF
{
 "admin-state": "enable",
 "interface-type": "point-to-point",
 "failure-detection": {
   "enable-bfd": true
 }
}
EOF
$GNMIC set --replace-path /network-instance[name=default]/protocols/ospf/instance[name=main]/area[area-id=0.0.0.0]/interface[interface-name=${INTF}.0] --replace-file $temp_file
exitcode+=$?
fi

# Enable BFD, except for host facing interfaces
cat > $temp_file << EOF
{
 "admin-state" : "enable",
 "desired-minimum-transmit-interval" : 250000,
 "required-minimum-receive" : 250000,
 "detection-multiplier" : 3
}
EOF
$GNMIC set --replace-path /bfd/subinterface[id=${INTF}.0] --replace-file $temp_file
exitcode+=$?
fi

if [[ "$PEER_IP" != "*" ]] && [[ "$PEER_TYPE" != "host" ]] && \
   [[ "$OSPF_ADMIN_STATE" == "disable" ]]; then
_IP="$PEER_IP"
# if [[ "$PEER" == "host" ]] || [[ "$PEER_TYPE" == "host" ]]; then
# PEER_GROUP="hosts"
# _IP="2001::${PEER_IP//\./:}" # Use ipv6 for hosts
if [[ "$ROLE" == "spine" ]]; then
PEER_GROUP="fellow-spines"
elif [[ "$ROLE" == "leaf" ]]; then
PEER_GROUP="spines"
else
PEER_GROUP="leaf-ibgp"
# _IP="2001::${PEER_IP//\./:}" # Use ipv6 for hosts
fi

cat > $temp_file << EOF
{
  "admin-state": "enable",
  "peer-group": "$PEER_GROUP",
  "description": "$PEER"
}
EOF
$GNMIC set --update-path /network-instance[name=$VRF]/protocols/bgp/neighbor[peer-address=$_IP] --update-file $temp_file
exitcode+=$?
fi

# Peer router ID only set for spines when this node is a leaf
if [[ "$ROLE" == "leaf" ]] && [[ "$PEER_ROUTER_ID" != "" ]] && [[ "$USE_EVPN_OVERLAY" == "1" ]]; then
cat > $temp_file << EOF
{ "admin-state": "enable", "peer-group": "evpn-rr", "description": "$PEER" }
EOF
$GNMIC set --update-path /network-instance[name=default]/protocols/bgp/neighbor[peer-address=$PEER_ROUTER_ID] --update-file $temp_file
exitcode+=$?
fi

rm -f $temp_file
exit $exitcode
