/set system gnmi-server unix-socket admin-state enable
set /auto-config-agent gateway ipv4 10.0.0.1/24 location spine
set /auto-config-agent igp bgp evpn model l2-only-leaves auto-lags encoded-ipv6 overlay-as 65536
