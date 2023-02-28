# auto-config for srl-evpn lab leaves & spines
set /system gnmi-server unix-socket admin-state enable
set /auto-config-agent gateway ipv4 10.0.0.1/24
set /auto-config-agent lacp active lacp-fallback 90 # reload-delay-secs 0
set /auto-config-agent igp ospf evpn model asymmetric-irb auto-lags encoded-ipv6 bgp-peering ipv4 overlay-as 65000
