#!/bin/sh

# Bring up network interfaces
ifup -a

# Run LLDP daemon, this runs in background by default
/usr/sbin/lldpd

# Run shell
/bin/sh
