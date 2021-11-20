#!/bin/sh

# Wait for interfaces to exist
for i in $(seq 0 $CLAB_INTFS); do
until [ -f /sys/class/net/eth${i}/carrier ];
do
  echo "Waiting for /sys/class/net/eth${i}/carrier"
  sleep 1
done
done
echo "All $CLAB_INTFS + eth0 are up!"

# Bring up network interfaces
ifup -a

# Run LLDP daemon, this runs in background by default
/usr/sbin/lldpd

# Run shell
/bin/sh
