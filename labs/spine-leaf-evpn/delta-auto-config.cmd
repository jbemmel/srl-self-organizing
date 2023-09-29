# set /auto-config-agent gateway ipv4 10.0.{port}.1/24

# auto-config for srl-evpn lab leaves & spines
set /system gnmi-server unix-socket admin-state enable use-authentication false
set /system gnmi-server rate-limit 65000
set /auto-config-agent igp bgp-unnumbered evpn model symmetric-irb auto-lags encoded-ipv6 bgp-peering ipv4
set /auto-config-agent gateway ipv4 10.0.0.1/24 ipv6 2001:10::1/64
set /auto-config-agent lacp active # reload-delay-secs 0
