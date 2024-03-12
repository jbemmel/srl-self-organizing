# set /auto-config-agent gateway ipv4 10.0.{port}.1/24

# auto-config for srl-evpn lab leaves & spines
set /system gnmi-server unix-socket admin-state enable use-authentication false
set /system gnmi-server rate-limit 65000
set /auto-config-agent igp isis-unnumbered evpn model symmetric-irb auto-lags encoded-ipv6 bgp-peering ipv4
set /auto-config-agent lacp active # reload-delay-secs 0

# Put each VRRP pair in a separate mac-vrf/ip-vrf
set /auto-config-agent ports-per-service 2 vrf-per-service true gateway ipv4 10.{vrf}.0.1/24 ipv6 2001:{vrf}::1/64
