#!/bin/bash

sysctl -w net.ipv4.conf.all.arp_ignore=1
sysctl -w net.ipv4.conf.all.arp_announce=1
sysctl -w net.ipv4.conf.all.arp_filter=0

sysctl -w net.ipv4.conf.bond0.arp_filter=1

sysctl -w net.ipv4.conf.vrrp/2.arp_filter=0
sysctl -w net.ipv4.conf.vrrp/2.accept_local=1 # (this is needed for the address owner case)
sysctl -w net.ipv4.conf.vrrp/2.rp_filter=0

# ipv6 equivalents don't exist
# sysctl -w net.ipv6.conf.all.arp_ignore=1
# sysctl -w net.ipv6.conf.all.arp_announce=1
# sysctl -w net.ipv6.conf.all.arp_filter=0
# 
# sysctl -w net.ipv6.conf.bond0.arp_filter=1
# 
# sysctl -w net.ipv6.conf.vrrp/2.arp_filter=0
# sysctl -w net.ipv6.conf.vrrp/2.accept_local=1 # (this is needed for the address owner case)
# sysctl -w net.ipv6.conf.vrrp/2.rp_filter=0