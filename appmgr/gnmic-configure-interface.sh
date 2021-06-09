#!/bin/bash

# Sample script to provision SRLinux using gnmic
ROLE="$1"  # "spine" or "leaf" or "endpoint"
INTF="$2"
IP_PREFIX="$3"
PEER="$4"         # 'host' for Linux nodes and endpoints
PEER_IP="$5"
AS="$6"
ROUTER_ID="$7"
PEER_AS_MIN="$8"
PEER_AS_MAX="$9"
LINK_PREFIX="${10}"  # IP subnet used for allocation of IPs to BGP peers
PEER_TYPE="${11}"
OSPF_ADMIN_STATE="${12}" # 'enable' or 'disable'

GNMIC="/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf"

temp_file=$(mktemp --suffix=.json)
_IP127="${IP_PREFIX//\/31/\/127}"
if [[ "$PEER_TYPE" != "host" ]] && [[ "$ROLE" != "endpoint" ]]; then
  _ROUTED='"type" : "routed",'
fi
if [[ "$PEER_TYPE" == "host" ]] || [[ "$ROLE" == "endpoint" ]]; then
  _VLAN_TAGGING='"vlan-tagging" : true,'
  _VLAN='"srl_nokia-interfaces-vlans:vlan": { "encap": { "single-tagged": { "vlan-id": 1 } } },'
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
      "admin-state": "enable",
      "ipv4": {
        "address": [
          {
            "ip-prefix": "$IP_PREFIX"
          }
        ]
      },
      "ipv6": {
        "address": [
          {
            "ip-prefix": "2001::${_IP127//\./:}"
          }
        ]
      }
    }
  ]
}
EOF

# For now, assume that the interface is already added to the default network-instance; only update its IP address
$GNMIC set --replace-path /interface[name=$INTF] --replace-file $temp_file
exitcode=$?

# Enable BFD, except for host facing interfaces
if [[ "$PEER_TYPE" != "host" ]] && [[ "$ROLE" != "endpoint" ]]; then
cat > $temp_file << EOF
{
 "admin-state" : "enable",
 "desired-minimum-transmit-interval" : 250000,
 "required-minimum-receive" : 250000,
 "detection-multiplier" : 3
}
EOF

$GNMIC set --replace-path /bfd/subinterface[id=${INTF}.0] --replace-file $temp_file
exitcode=$?
fi

# Set loopback IP, if provided
if [[ "$ROUTER_ID" != "" ]]; then
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
$GNMIC set --replace-path /interface[name=lo0] --replace-file $temp_file
exitcode+=$?

# TODO more incremental, interfaces should be added based on LLDP events
cat > $temp_file << EOF
{
  "router-id": "$ROUTER_ID",
  "admin-state": "$OSPF_ADMIN_STATE",
  "version": "ospf-v3",
  "address-family": "ipv6-unicast",
  "max-ecmp-paths": 8,
  "area": [
    {
      "area-id": "0.0.0.0",
      "interface": [
        {
          "interface-name": "${INTF}.0",
          "interface-type": "point-to-point"
        },
        {
          "interface-name": "lo0.0",
          "interface-type": "broadcast",
          "passive": true
        }
      ]
    }
  ]
}
EOF
$GNMIC set --update-path /network-instance[name=default]/protocols/ospf/instance[name=main] --update-file $temp_file
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
    }
  ]
}
EOF

# Or replace to reset all to a known state?
$GNMIC set --update-path /routing-policy --update-file $temp_file
exitcode+=$?

if [[ "$ROLE" == "spine" ]]; then
IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"dynamic-neighbors": {
    "accept": {
      "match": [
        {
          "prefix": "$LINK_PREFIX",
          "peer-group": "leaves",
          "allowed-peer-as": [
            "$PEER_AS_MIN..$PEER_AS_MAX"
          ]
        }
      ]
    }
  },
"failure-detection": { "enable-bfd" : true, "fast-failover" : true },
"group": [
    {
      "group-name": "fellow-spines",
      "admin-state": "enable",
      "peer-as": $AS
    },
    {
      "group-name": "leaves",
      "admin-state": "enable",
      "import-policy": "select-loopbacks",
      "export-policy": "select-loopbacks"
    },
    {
      "group-name": "evpn",
      "admin-state": "enable",
      "peer-as": $AS,
      "evpn": {
        "admin-state": "enable"
      },
      "route-reflector": {
        "client": true,
        "cluster-id": "$ROUTER_ID"
      }
    }
  ],
EOF
elif [[ "$ROLE" == "leaf" ]]; then
IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"group": [
    {
      "group-name": "spines",
      "admin-state": "enable",
      "import-policy": "select-loopbacks",
      "export-policy": "select-loopbacks",
      "failure-detection": { "enable-bfd" : true, "fast-failover" : true },
      "peer-as": $PEER_AS_MIN
    },
    {
      "group-name": "hosts",
      "admin-state": "enable",
      "ipv6-unicast" : { "admin-state" : "enable" },
      "peer-as": $AS
    },
    {
      "group-name": "evpn-rr",
      "admin-state": "enable",
      "peer-as": $PEER_AS_MIN,
      "evpn": {
        "admin-state": "enable"
      }
    }
],
EOF
else
IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"group": [
    {
      "group-name": "leaf-ibgp",
      "admin-state": "enable",
      "ipv6-unicast" : { "admin-state" : "enable" },
      "peer-as": $AS
    }
],
EOF
fi

cat > $temp_file << EOF
{
  "admin-state": "enable",
  "autonomous-system": $AS,
  "router-id": "$ROUTER_ID", "_annotate_router-id": "${ROUTER_ID##*.}",
  $DYNAMIC_NEIGHBORS
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

fi # if router_id provided, first time only

if [[ "$PEER_IP" != "*" ]]; then
_IP="$PEER_IP"
if [[ "$PEER" == "host" ]] || [[ "$PEER_TYPE" == "host" ]]; then
PEER_GROUP="hosts"
# _IP="2001::${PEER_IP//\./:}" # Use ipv6 for hosts
elif [[ "$ROLE" == "spine" ]]; then
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
  "peer-group": "$PEER_GROUP"
}
EOF
$GNMIC set --update-path /network-instance[name=default]/protocols/bgp/neighbor[peer-address=$_IP] --update-file $temp_file
exitcode+=$?
fi

rm -f $temp_file
exit $exitcode
