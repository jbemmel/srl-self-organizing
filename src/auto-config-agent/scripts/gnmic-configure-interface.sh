#!/bin/bash

# Sample script to provision SRLinux using gnmic
# TODO next version: Use Jinja2 templates plus native Python logic instead
#
#
ROLE="$1"  # "spine" or "leaf" or "endpoint" or "superspine"
INTF="$2"
IP_PREFIX="$3"
PEER="$4"         # 'host' for Linux nodes and endpoints
PEER_IP="$5"
ROUTER_ID="$6"
PEER_AS_MIN="$7"     # Overlay AS in case of leaf-host
PEER_AS_MAX="$8"     # Host AS in case of leaf-host
LINK_PREFIX="${9}"  # IP subnet used for allocation of IPs to BGP peers
PEER_TYPE="${10}"
PEER_ROUTER_ID="${11}" # Not currently used
IGP="${12}" # 'bgp' or 'isis' or 'ospf'
USE_EVPN_OVERLAY="${13}" # 'disabled', 'symmetric_irb' or 'asymmetric_irb'
OVERLAY_BGP_ADMIN_STATE="${14}" # 'disable' or 'enable'

# echo "DEBUG: ROUTER_ID='$ROUTER_ID'"
# echo "DEBUG: EVPN overlay AS=${evpn_overlay_as}"

# Can add --debug
GNMIC="/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf"

temp_file=$(mktemp --suffix=.json)
exitcode=0

#
# 1) One-time configuration at startup, when ROUTER_ID is provided
#
if [[ "$ROUTER_ID" != "" ]]; then

if [[ "${disable_icmp_ttl0_rate_limiting}" == "True" ]]; then
 echo "Disabling ICMP TTL 0 rate limiting in srbase-default by setting net.ipv4.icmp_ratemask=4120"
 # Setting is per netns (could put this in a separate agent...)
 /sbin/ip netns exec srbase-default sudo sysctl -w net.ipv4.icmp_ratemask=4120
fi

if [[ "$ROLE" == "leaf" ]]; then
# XXX cannot ping system0 interface? may want to create lo0.0 with ipv6 addr
LOOPBACK_IF="system"
LOOPBACK_IP4="$ROUTER_ID/31" # Use /31 to have multiple source IPs for traceroute
LOOPBACK_IP6="2001::${ROUTER_ID//\./:}/127"
else
LOOPBACK_IF="lo"
LOOPBACK_IP4="$ROUTER_ID/32"
LOOPBACK_IP6="2001::${ROUTER_ID//\./:}/128"
fi

cat > $temp_file << EOF
{
  "admin-state": "enable",
  "subinterface": [
    {
      "index": 0,
      "admin-state": "enable",
      "ipv4": { "address": [ { "ip-prefix": "$LOOPBACK_IP4" } ] },
      "ipv6": { "address": [ { "ip-prefix": "$LOOPBACK_IP6" } ] }
    }
  ]
}
EOF
# Cannot do 'replace' here, other subinterfaces used
$GNMIC set --update-path /interface[name=${LOOPBACK_IF}0] --update-file $temp_file
exitcode+=$?

# Enable BFD for loopback
if [[ "$enable_bfd" == "true" ]]; then
cat > $temp_file << EOF
{
 "admin-state" : "enable",
 "desired-minimum-transmit-interval" : 250000,
 "required-minimum-receive" : 250000,
 "detection-multiplier" : 3
}
EOF
$GNMIC set --replace-path /bfd/subinterface[id=${LOOPBACK_IF}0.0] --replace-file $temp_file
exitcode+=$?
fi

$GNMIC set --update /network-instance[name=default]/interface[name=${LOOPBACK_IF}0.0]:::string:::''
exitcode+=$?

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
    },
    {
      "name": "links",
      "prefix": [
        { "ip-prefix": "$LINK_PREFIX","mask-length-range": "28..31" }
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
      "name": "reject-link-routes",
      "default-action": { "accept": { } },
      "statement": [
        {
          "sequence-id": 10,
          "match": {
            "prefix-set": "links"
          },
          "action": { "reject": { } }
        }
      ]
    },
    {
      "name": "accept-all",
      "default-action": { "accept": { } }
    }
  ]
}
EOF

# Or replace to reset all to a known state?
$GNMIC set --update-path /routing-policy --update-file $temp_file
exitcode+=$?

# Use ipv6 link local addresses to advertise ipv4 VXLAN system ifs via OSPFv3
# Still requires static (link local) IPv4 addresses on each interface
if [[ "$IGP" == "ospf" ]]; then

if [[ "$ROLE" == "spine" ]]; then
IFS='' read -r -d '' ENABLE_ASBR_ON_SPINE << EOF
"asbr": {
  "_annotate": "Redistribute indirect routes including static routes"
},
"export-policy": "accept-all",
EOF
fi

cat > $temp_file << EOF
{
  "router-id": "$ROUTER_ID",
  "admin-state": "enable",
  "version": "ospf-v3",
  "address-family": "ipv4-unicast",
  "max-ecmp-paths": 8,
  ${ENABLE_ASBR_ON_SPINE}
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

elif [[ "$IGP" == "isis" ]]; then

IFS=. read ip1 ip2 ip3 ip4 <<< "$ROUTER_ID"
NET_ID=$( printf "49.0001.9999.%02x%02x.%02x%02x.00" $ip1 $ip2 $ip3 $ip4 )

cat > $temp_file << EOF
{
      "admin-state": "enable",
      "level-capability": "L1",
      "max-ecmp-paths": 8,
      "net": [
        "$NET_ID"
      ],
      "ipv4-unicast": {
        "admin-state": "enable"
      },
      "ipv6-unicast": {
        "admin-state": "enable"
      },
      "interface": [
       {
        "interface-name": "${LOOPBACK_IF}0.0",
        "admin-state": "enable",
        "passive": true
       }
      ]
}
EOF
$GNMIC set --update-path /network-instance[name=default]/protocols/isis/instance[name=main] --update-file $temp_file
exitcode+=$?
fi

if [[ $ROLE =~ ^(super)?spine ]]; then

if [[ "$IGP" == "bgp" ]]; then

if [[ "$ROLE" == "spine" ]]; then
# May or may not be used
#
# Could also use "as-path-options": { "allow-own-as": 1(or 2 on leaves) },
# instead of "prepend-global-as": false
#
IFS='' read -r -d '' EBGP_PEER_GROUP_SUPERSPINES << EOF
  ,{
    "group-name": "ebgp-superspines",
    "admin-state": "enable",
    "import-policy": "select-loopbacks",
    "export-policy": "select-loopbacks",
    "failure-detection": { "enable-bfd" : ${enable_bfd}, "fast-failover" : true },
    "timers": { "connect-retry": 10 },
    "local-as": [ { "as-number": ${local_as}, "prepend-global-as": false } ],
    "peer-as": ${PEER_AS_MIN}
  }
EOF
DYNAMIC_EBPG_GROUP="ebgp-leaves"
else
DYNAMIC_EBPG_GROUP="ebgp-spines"
IFS='' read -r -d '' AS_PATH_OPTIONS << EOF
"as-path-options": {
    "replace-peer-as": true,
    "_annotate_replace-peer-as": "To allow routes across spines"
},
EOF
fi

IFS='' read -r -d '' DYNAMIC_EBGP_NEIGHBORS << EOF
{
  "prefix": "$LINK_PREFIX",
  "peer-group": "${DYNAMIC_EBPG_GROUP}"
}
EOF
EBGP_NEIGHBORS_COMMA=","

IFS='' read -r -d '' EBGP_PEER_GROUP << EOF
{
  "group-name": "${DYNAMIC_EBPG_GROUP}",
  "admin-state": "enable",
  "import-policy": "select-loopbacks",
  "export-policy": "select-loopbacks",
  "failure-detection": { "enable-bfd" : ${enable_bfd}, "fast-failover" : true },
  ${AS_PATH_OPTIONS}
  "local-as": [ { "as-number": ${local_as}, "prepend-global-as": false } ]
}
${EBGP_PEER_GROUP_SUPERSPINES},
EOF

fi

#
# Enable all (super)spines to be EVPN Route Reflectors, may not get used
#
if [[ "$USE_EVPN_OVERLAY" != "disabled" && ("$ROLE"=="$evpn_rr" || \
    ("$evpn_rr"=="auto_top_nodes" && ("$ROLE"=="superspine" || ("$ROLE"=="spine" && "$max_level"=="1")))) ]]; then
IFS='' read -r -d '' EVPN_LEAVES_GROUP << EOF
{
  "group-name": "evpn-leaves",
  "admin-state": "enable",
  "peer-as": ${evpn_overlay_as},
  "_annotate_peer-as": "iBGP with leaves",
  "evpn": { "admin-state": "enable" },
  "ipv4-unicast": { "admin-state": "disable" },
  "ipv6-unicast": { "admin-state": "disable" },
  "route-reflector": {
    "client": true,
    "cluster-id": "$ROUTER_ID"
  }
}
EOF

IFS=. read ip1 ip2 ip3 ip4 <<< "$ROUTER_ID"

IFS='' read -r -d '' EVPN_IBGP_NEIGHBORS << EOF
$EBGP_NEIGHBORS_COMMA {
  "prefix": "$ip1.$ip2.0.0/24",
  "peer-group": "evpn-leaves",
  "allowed-peer-as": [ "${evpn_overlay_as}" ]
}
EOF

IFS='' read -r -d '' EVPN_SECTION << EOF
"evpn": {
 "rapid-update": true ,
 "keep-all-routes": true,
 "_annotate_keep-all-routes": "implicitly enabled for route-reflectors"
},
EOF
fi

IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"dynamic-neighbors": {
    "accept": {
      "match": [
        ${DYNAMIC_EBGP_NEIGHBORS}
        ${EVPN_IBGP_NEIGHBORS}
      ]
    }
},
"failure-detection": { "enable-bfd" : ${enable_bfd}, "fast-failover" : true },
${EVPN_SECTION}
"group": [
    ${EBGP_PEER_GROUP}
    ${EVPN_LEAVES_GROUP}
],
EOF
elif [[ "$ROLE" == "leaf" ]]; then

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

IFS='' read -r -d '' HOSTS_GROUP << EOF
{
  "group-name": "hosts",
  "admin-state": "$OVERLAY_BGP_ADMIN_STATE",
  "ipv6-unicast" : { "admin-state" : "enable" },
  "local-as": [ { "as-number": ${evpn_overlay_as} } ],
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
          "peer-group": "hosts"
        }
      ]
    }
}
EOF

if [[ "$USE_EVPN_OVERLAY" != "disabled" ]]; then
DEFAULT_HOSTS_GROUP=""
DEFAULT_DYNAMIC_HOST_PEERING=""
IFS='' read -r -d '' EVPN_RR_GROUP << EOF
{
  "group-name": "evpn-rr",
  "admin-state": "enable",
  "import-policy": "accept-all",
  "export-policy": "reject-link-routes",
  "peer-as": ${evpn_overlay_as},
  "local-as": [ { "as-number": ${evpn_overlay_as} } ],
  "evpn": { "admin-state": "enable" },
  "transport" : { "local-address" : "${ROUTER_ID}" },
  "timers": { "connect-retry": 10 }
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

if [[ "$IGP" == "bgp" ]]; then
IFS='' read -r -d '' SPINES_GROUP << EOF
{
  "group-name": "ebgp-spines",
  "admin-state": "enable",
  "import-policy": "select-loopbacks",
  "export-policy": "select-loopbacks",
  "failure-detection": { "enable-bfd" : ${enable_bfd}, "fast-failover" : true },
  "timers": { "connect-retry": 10 },
  "peer-as": $PEER_AS_MIN,
  "local-as": [ { "as-number": ${local_as}, "prepend-global-as": false } ]
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
"evpn": {
  "rapid-update": true,
  "keep-all-routes": true,
  "_annotate_keep-all-routes": "to avoid route-refresh messages attracting all EVPN routes when policy changes or bgp-evpn is enabled"
},
"failure-detection": { "enable-bfd" : ${enable_bfd}, "fast-failover" : true },
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
  "autonomous-system": ${evpn_overlay_as},
  "_annotate_autonomous-system": "this is the overlay AS, (also) used for auto-derived RT",
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

# For leaves, create L3 VXLAN tunnel interface vxlan0 for overlay VRF
if [[ "$ROLE" == "leaf" ]] && [[ "$USE_EVPN_OVERLAY" != "disabled" ]]; then

if [[ "$USE_EVPN_OVERLAY" == "symmetric_irb" ]]; then
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

L3_VXLAN_INTERFACE='"vxlan-interface": [ { "name": "vxlan0.0", "_annotate": "This is symmetric IRB with a L3 VXLAN interface and EVPN RT5 routes" } ],'

IFS='' read -r -d '' IP_VRF_BGP_EVPN << EOF
,"bgp-evpn": {
  "bgp-instance": [
    {
      "id": 1,
      "admin-state": "enable",
      "vxlan-interface": "vxlan0.0",
      "evi": 10000,
      "ecmp": 8
    }
  ]
},"bgp-vpn": {
  "bgp-instance": [
    {
      "id": 1,
      "_annotate": "Required to make bgp-evpn oper-state=up"
    }
  ]
}
EOF
else
L3_VXLAN_INTERFACE='"_annotate": "This is asymmetric IRB, no BGP-EVPN or vxlan interface in this ip-vrf",'
fi

# Configure lo0.0 on Leaf with router IP for ping testing in overlay
cat > $temp_file << EOF
{
  "admin-state": "enable",
  "subinterface": [
    {
      "index": 0,
      "description": "Overlay loopback",
      "admin-state": "enable",
      "ipv4": { "address": [ { "ip-prefix": "$ROUTER_ID/32" } ] },
      "ipv6": { "address": [ { "ip-prefix": "2001::${ROUTER_ID//\./:}/128" } ] }
    }
  ]
}
EOF
$GNMIC set --update-path /interface[name=lo0] --update-file $temp_file
exitcode+=$?

# Set autonomous system & router-id for BGP to hosts
# Assumes a L3 service
# This is symmetric IRB (with VXLAN interfaces in both mac-vrf and ip-vrf)
cat > $temp_file << EOF
{
    "type": "srl_nokia-network-instance:ip-vrf",
    "_annotate_type": "routed",
    "admin-state": "enable",
    "interface": [ { "name": "lo0.0" } ],
    $L3_VXLAN_INTERFACE
    "protocols": {
      "bgp": {
        "admin-state": "enable",
        "autonomous-system": ${evpn_overlay_as},
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
      }
      $IP_VRF_BGP_EVPN
    }
  }
EOF
$GNMIC set --update-path /network-instance[name=overlay] --update-file $temp_file
exitcode+=$?

fi # leaf with EVPN enabled
fi # if ROUTER_ID provided, first time only

#
# 2) Per-link provisioning
#

if [[ "$PEER_TYPE" != "host" ]] && [[ "$ROLE" != "endpoint" ]]; then
  _ROUTED='"type" : "routed",'
fi
#if [[ "$PEER_TYPE" == "host" ]] || [[ "$ROLE" == "endpoint" ]]; then
#  _VLAN_TAGGING='"vlan-tagging" : true,'
#  _VLAN='"srl_nokia-interfaces-vlans:vlan": { "encap": { "single-tagged": { "vlan-id": 1 } } },'
#fi
if [[ "${IP_PREFIX}" != "" ]]; then

# Replace ipv4 prefix with /127 for ipv6
if [[ "$PEER_TYPE" != "host" ]]; then
_IP127=":${IP_PREFIX//\/31/\/127}"
else
# Use /64 towards each host
_IP127="${IP_PREFIX//\/[23][0-9]/::\/64}"
fi
IFS='' read -r -d '' _IP_ADDRESSING << EOF
,"ipv4": { "address": [ { "ip-prefix": "$IP_PREFIX" } ] },
 "ipv6": { "address": [ { "ip-prefix": "2001:${_IP127//\./:}" } ] }
EOF
else
# Enable IPv4+IPv6 but don't put addresses (yet)
IFS='' read -r -d '' _IP_ADDRESSING << EOF
,"ipv4": {  },
 "ipv6": {  }
EOF
fi

# Removed $_VLAN_TAGGING and $_VLAN
cat > $temp_file << EOF
{
  "description": "auto-config to $PEER",
  "admin-state": "enable",
  "subinterface": [
    {
      "index": 0,
      $_ROUTED
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
if [[ "$ROLE" == "leaf" ]] && [[ "$PEER_TYPE" == "host" ]] && [[ "$USE_EVPN_OVERLAY" != "disabled" ]]; then
VRF="overlay"
else
VRF="default"
fi
$GNMIC set --update /network-instance[name=$VRF]/interface[name=${INTF}.0]:::string:::''
exitcode+=$?

# Add it to OSPF (if enabled)
# Note: To view: info from state /bfd
if [[ "$ROLE" != "endpoint" ]]; then

if [[ "$IGP" == "ospf" && "$PEER_TYPE" != "host" ]]; then
cat > $temp_file << EOF
{
 "admin-state": "enable",
 "interface-type": "point-to-point",
 "failure-detection": {
   "enable-bfd": ${enable_bfd}
 }
}
EOF
$GNMIC set --replace-path /network-instance[name=default]/protocols/ospf/instance[name=main]/area[area-id=0.0.0.0]/interface[interface-name=${INTF}.0] --replace-file $temp_file
exitcode+=$?

elif [[ "$IGP" == "isis" && "$PEER_TYPE" != "host" ]]; then
cat > $temp_file << EOF
{
 "admin-state": "enable",
 "ipv4-unicast": { "admin-state": "disable" },
 "ipv6-unicast": { "admin-state": "enable", "enable-bfd": ${enable_bfd} }
}
EOF
$GNMIC set --replace-path /network-instance[name=default]/protocols/isis/instance[name=main]/interface[interface-name=${INTF}.0] --replace-file $temp_file
exitcode+=$?

elif [[ "$IGP" == "bgp" || "$PEER_TYPE" == "host" ]]; then

if [[ "$PEER_IP" != "*" ]]; then
cat > $temp_file << EOF
{
  "admin-state": "enable",
  "peer-group": "ebgp-${PEER_TYPE}s",
  "description": "$PEER"
}
EOF
echo "Adding BGP peer ${PEER_IP} in VRF ${VRF}..."
$GNMIC set --update-path /network-instance[name=$VRF]/protocols/bgp/neighbor[peer-address=$PEER_IP] --update-file $temp_file
exitcode+=$?
else

# Update EBGP dynamic peering group on (super)spines and leaves with correct AS range
cat > $temp_file << EOF
{
  "allowed-peer-as": [
    "$PEER_AS_MIN..$PEER_AS_MAX"
  ]
}
EOF
$GNMIC set --update-path /network-instance[name=$VRF]/protocols/bgp/dynamic-neighbors/accept/match[prefix=$LINK_PREFIX] --update-file $temp_file
exitcode+=$?

fi # "$PEER_IP" != "*"
fi # IGP logic

# Enable BFD, except for host facing interfaces
if [[ "$PEER_TYPE" != "host" ]]; then
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
fi # "$PEER_TYPE" != "host"
fi # $ROLE != "endpoint"

# Handle evpn_rr=="spine" case here, on a per-uplink basis
if [[ "$ROLE" == "leaf" && "$PEER_TYPE" == "spine" && "$USE_EVPN_OVERLAY" != "disabled" && "$evpn_rr" == "spine" ]]; then
cat > $temp_file << EOF
{ "admin-state": "enable", "peer-group": "evpn-rr", "description": "EVPN Route Reflector for overlay" }
EOF
echo "Adding spine BGP peer ${PEER_ROUTER_ID} as EVPN route reflector..."
$GNMIC set --update-path /network-instance[name=default]/protocols/bgp/neighbor[peer-address=$PEER_ROUTER_ID] --update-file $temp_file
exitcode+=$?
fi

echo "Done, cleaning up ${temp_file}..."
rm -f $temp_file
exit $exitcode
