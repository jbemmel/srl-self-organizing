#!/bin/bash

# Temporary script to provision an interface using gnmic, complicated to pass JSON objects

INTF="$1"
IP_PREFIX="$2"
PEER="$3"
PEER_IP="$4"
AS="$5"
ROUTER_ID="$6"

temp_file=$(mktemp --suffix=.json)
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
      }
    }
  ]
}
EOF

# For now, assume that the interface is already added to the default network-instance; only update its IP address
/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --replace-path /interface[name=$INTF] --replace-file $temp_file
exitcode=$?

if [[ "$PEER_IP" == "*" ]]; then
IFS='' read -r -d '' DYNAMIC_NEIGHBORS << EOF
"dynamic-neighbors": {
    "accept": {
      "match": [
        {
          "prefix": "192.168.0.0/24",
          "peer-group": "leaves",
          "allowed-peer-as": [
            "65001..65002"
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
      "export-policy": "export-hosts",
      "peer-as": 65000
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
  "ebgp-default-policy": {
    "import-reject-all": false,
    "export-reject-all": false
  },
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
/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --replace-path /network-instance[name=default]/protocols/bgp --replace-file $temp_file
exitcode+=$?

if [[ "$PEER_IP" != "*" ]]; then
cat > $temp_file << EOF
{
  "admin-state": "enable",
  "peer-group": "spines"
}
EOF
/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --update-path /network-instance[name=default]/protocols/bgp/neighbor[peer-address=$PEER_IP] --update-file $temp_file
exitcode+=$?
fi

rm -f $temp_file
exit $exitcode
