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

/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --replace-path /interface[name=$INTF] --replace-file $temp_file
exitcode=$?
# For now, assume that the interface is already added to the default network-instance; only update its IP address

if [[ "$PEER_IP" != "" ]]; then
cat > $temp_file << EOF
{
  "admin-state": "enable",
  "autonomous-system": $AS,
  "router-id": "$ROUTER_ID",
  "ebgp-default-policy": {
    "import-reject-all": false,
    "export-reject-all": false
  },
  "group": [
    {
      "group-name": "spines",
      "admin-state": "enable",
      "export-policy": "export-hosts",
      "peer-as": 65000
    }
  ],
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
  "neighbor": [
    {
      "peer-address": "$PEER_IP",
      "admin-state": "enable",
      "peer-group": "spines"
    }
  ],
  "route-advertisement": {
    "rapid-withdrawal": true
  }
}

EOF
/sbin/ip netns exec srbase-mgmt /usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set \
  --update-path /network-instance[name=default]/protocols/bgp --update-file $temp_file
fi

rm -f $temp_file
exit $exitcode
