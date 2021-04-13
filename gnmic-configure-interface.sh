#!/bin/bash

# Temporary script to provision an interface using gnmic, complicated to pass JSON objects

INTF="$1"
IP_PREFIX="$2"
PEER="$3"

temp_file=$(mktemp --suffix=.json)
cat > $temp_file <<< EOF
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

/usr/local/bin/gnmic -a 127.0.0.1:57400 -u admin -p admin --skip-verify -e json_ietf set --update-path /interface[name=$INTF] --update-file $temp_file

# For now, assume that the interface is already added to the default network-instance; only update its IP address

rm -f $temp_file
