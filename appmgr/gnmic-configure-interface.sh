#!/bin/bash

# Sample script to provision SRLinux using gnmic

INTF="$1"
IP_PREFIX="$2"
PEER="$3"         # 'host' for Linux nodes
PEER_IP="$4"
AS="$5"
ROUTER_ID="$6"
PEER_AS_MIN="$7"
PEER_AS_MAX="$8"
LINK_PREFIX="$9"  # IP subnet used for allocation of IPs to BGP peers

temp_file=$(mktemp --suffix=.json)
_IP127="${IP_PREFIX//\/31/\/127}"
cat > $temp_file << EOF
{
  "description": "To $PEER",
  "admin-state": "enable",
  "subinterface": [
    {
      "index": 0,
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
/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --replace-path /interface[name=$INTF] --replace-file $temp_file
exitcode=$?

# Set loopback IP, TODO only once not every LLDP message
cat > $temp_file << EOF
{
  "admin-state": "enable",
  "subinterface": [
    {
      "index": 0,
      "admin-state": "enable",
      "ipv4": {
        "address": [
          {
            "ip-prefix": "$ROUTER_ID/32"
          }
        ]
      }
    }
  ]
}
EOF
/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --replace-path /interface[name=lo0] --replace-file $temp_file
exitcode+=$?

if [[ "$PEER_IP" == "*" ]]; then
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
"group": [
    {
      "group-name": "leaves",
      "admin-state": "enable"
    }
  ],
EOF
else
IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"group": [
    {
      "group-name": "spines",
      "admin-state": "enable",
      "peer-as": $PEER_AS_MIN
    },
    {
      "group-name": "hosts",
      "admin-state": "enable",
      "peer-as": $AS
    }
],
EOF
fi

cat > $temp_file << EOF
{
  "admin-state": "enable",
  "autonomous-system": $AS,
  "router-id": "$ROUTER_ID",
  $DYNAMIC_NEIGHBORS
  "ipv4-unicast": {
    "multipath": {
      "max-paths-level-1": 4,
      "max-paths-level-2": 4
    }
  },
  "ipv6-unicast": {
    "multipath": {
      "max-paths-level-1": 4,
      "max-paths-level-2": 4
    }
  },
  "route-advertisement": {
    "rapid-withdrawal": true
  }
}

EOF

# Replace allows max 1 peer, TODO only add neighbors when already configured?
if [[ "$PEER" != "host" ]]; then
/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --update-path /network-instance[name=default]/protocols/bgp --update-file $temp_file
exitcode+=$?
fi

if [[ "$PEER_IP" != "*" ]]; then

if [[ "$PEER" == "host" ]]; then
PEER_GROUP="hosts"
_IP="2001::${PEER_IP//\./:}" # Use ipv6 for hosts
else
PEER_GROUP="spines"
_IP="$PEER_IP"
fi

cat > $temp_file << EOF
{
  "admin-state": "enable",
  "peer-group": "$PEER_GROUP"
}
EOF
/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --update-path /network-instance[name=default]/protocols/bgp/neighbor[peer-address=$_IP] --update-file $temp_file
exitcode+=$?
fi

rm -f $temp_file
exit $exitcode
