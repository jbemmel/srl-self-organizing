def routing_policy(is_leaf, link_prefix):
    NO_ADVERTISE = {"bgp": {"communities": {"add": "no-advertise"}}} if is_leaf else {}

    return {
        "prefix-set": [
            {
                "name": "loopbacks",
                "prefix": [
                    {"ip-prefix": "0.0.0.0/0", "mask-length-range": "32..32"},
                    {"ip-prefix": "::/0", "mask-length-range": "128..128"},
                ],
            },
            {
                "name": "links",
                "prefix": [{"ip-prefix": link_prefix, "mask-length-range": "28..31"}],
            },
        ],
        "community-set": [{"name": "no-advertise", "member": ["no-advertise"]}],
        "policy": [
            {
                "name": "import-loopbacks",
                "default-action": {"policy-result": "reject"},
                "statement": [
                    {
                        "name": "10",
                        "match": {"prefix-set": "loopbacks"},
                        "action": {"policy-result": "accept", **NO_ADVERTISE},
                    }
                ],
            },
            {
                "name": "export-loopbacks",
                "default-action": {"policy-result": "reject"},
                "statement": [
                    {
                        "name": "10",
                        "match": {"prefix-set": "loopbacks"},
                        "action": {"policy-result": "accept"},
                    }
                ],
            },
            {
                "name": "reject-link-routes",
                "default-action": {"policy-result": "accept"},
                "statement": [
                    {
                        "name": "10",
                        "match": {"prefix-set": "links"},
                        "action": {"policy-result": "reject"},
                    }
                ],
            },
            {"name": "accept-all", "default-action": {"policy-result": "accept"}},
        ],
    }


def ospf(router_id, is_spine):
    ENABLE_ASBR_ON_SPINE = {
        "asbr": {"_annotate": "Redistribute indirect routes including static routes"},
        "export-policy": "accept-all",
    }

    return {
        "router-id": router_id,
        "admin-state": "enable",
        "version": "ospf-v3",
        "address-family": "ipv4-unicast",
        "max-ecmp-paths": 8,
        **ENABLE_ASBR_ON_SPINE,
        "area": [
            {
                "area-id": "0.0.0.0",
                "interface": [
                    {
                        "admin-state": "enable",
                        "interface-name": "system0.0",
                        "passive": True,
                    }
                ],
            }
        ],
    }


def isis(router_id):
    oc = router_id.split(".")
    NET_ID = "49.0001.9999.{:02x}{:02x}{:02x}{:02x}.00".format(
        oc[0], oc[1], oc[2], oc[3]
    )

    return {
        "admin-state": "enable",
        "level-capability": "L1",
        "max-ecmp-paths": 8,
        "net": [NET_ID],
        "ipv4-unicast": {"admin-state": "enable"},
        "ipv6-unicast": {"admin-state": "enable"},
        "interface": [
            {"interface-name": "system0.0", "admin-state": "enable", "passive": True}
        ],
    }


def ebgp(
    router_id,
    evpn_overlay_as,
    local_as,
    enable_bfd,
):
    return {
        "admin-state": "enable",
        "afi-safi": [
            {
                "afi-safi-name": "ipv4-unicast",
                "admin-state": "enable",  # At least one AF must be enabled
                "multipath": {
                    "max-paths-level-1": 8,
                    "max-paths-level-2": 8,
                },
            },
            {
                "afi-safi-name": "ipv6-unicast",
                "multipath": {"max-paths-level-1": 8, "max-paths-level-2": 8},
            },
        ],
        "autonomous-system": evpn_overlay_as,
        "_annotate_autonomous-system": "this is the overlay AS, (also) used for auto-derived RT",
        "router-id": router_id,
        "_annotate_router-id": router_id.split(".")[3],
        "route-advertisement": {"rapid-withdrawal": True},
        "group": [
            {
                "group-name": "ebgp-peers",
                "admin-state": "enable",
                "import-policy": "import-loopbacks",
                "export-policy": "export-loopbacks",
                "failure-detection": {"enable-bfd": enable_bfd, "fast-failover": True},
                "timers": {"connect-retry": 10},
                "local-as": {"as-number": local_as, "prepend-global-as": False},
                "afi-safi": [
                    {"afi-safi-name": "ipv4-unicast", "admin-state": "enable"},
                    {"afi-safi-name": "ipv6-unicast", "admin-state": "enable"},
                ],
            }
        ],
    }


def interface(ip_prefix, peer_type, role):
    def ipv6():
        if peer_type != "host":
            ip = ip_prefix.replace("/31", "/127")
        else:
            ip = ip_prefix.replace("/[23][0-9]", "/64")
        return ip.replace(".", ":")

    IP_ADDRESSING = (
        {
            "ipv4": {"address": [{"ip-prefix": ip_prefix}], "admin-state": "enable"},
            "ipv6": {"address": [{"ip-prefix": ipv6()}], "admin-state": "enable"},
        }
        if ip_prefix
        else {}
    )

    ROUTED = {"type": "routed"} if peer_type != "host" and role != "endpoint" else {}

    return {
        "description": "auto-config to $PEER",
        "admin-state": "enable",
        "subinterface": [
            {"index": 0, **ROUTED, "admin-state": "enable", **IP_ADDRESSING}
        ],
    }


def bfd():
    return {
        "admin-state": "enable",
        "desired-minimum-transmit-interval": 250000,
        "required-minimum-receive": 250000,
        "detection-multiplier": 3,
    }


def bgp_evpn(router_id, evpn_overlay_as, evpn_bgp_peering, use_ipv6_nexthops):
    TRANSPORT = (
        router_id
        if evpn_bgp_peering == "ipv4"
        else f"2001::{router_id.replace('.',':')}"
    )
    return {
        "group-name": "evpn-rr",
        "admin-state": "enable",
        "import-policy": "accept-all",
        "export-policy": "reject-link-routes",  # Reject overlay link routes
        "peer-as": evpn_overlay_as,
        "local-as": {"as-number": evpn_overlay_as},
        "afi-safi": [
            {
                "afi-safi-name": "evpn",
                "admin-state": "enable",
                "evpn": {"advertise-ipv6-next-hops": use_ipv6_nexthops},
            },
            {"afi-safi-name": "ipv4-unicast", "admin-state": "disable"},
        ],
        "transport": {"local-address": TRANSPORT},
        "timers": {"connect-retry": 10},
    }


# Could merge with bgp_evpn
def bgp_evpn_rr_clients(
    router_id, evpn_overlay_as, evpn_bgp_peering, use_ipv6_nexthops
):
    ip = router_id.split(".")
    NBR_PREFIX = (
        f"{ip[0]}.{ip[1]}.0.0/16" if evpn_bgp_peering == "ipv4" else "2001::/16"
    )
    TRANSPORT = (
        router_id
        if evpn_bgp_peering == "ipv4"
        else f"2001::{router_id.replace('.',':')}"
    )
    return {
        "dynamic-neighbors": {
            "accept": {
                "match": [
                    {
                        "prefix": NBR_PREFIX,
                        "peer-group": "evpn-rr-clients",
                        "allowed-peer-as": [evpn_overlay_as],
                    }
                ]
            }
        },
        "group": [
            {
                "group-name": "evpn-rr-clients",
                "admin-state": "enable",
                "import-policy": "accept-all",
                "export-policy": "accept-all",
                "peer-as": evpn_overlay_as,
                "local-as": {"as-number": evpn_overlay_as},
                "afi-safi": [
                    {
                        "afi-safi-name": "evpn",
                        "admin-state": "enable",
                        "evpn": {"advertise-ipv6-next-hops": use_ipv6_nexthops},
                    },
                    {"afi-safi-name": "ipv4-unicast", "admin-state": "disable"},
                ],
                "transport": {"local-address": TRANSPORT},
                "timers": {"connect-retry": 10},
            }
        ],
    }


def ospf_intf(enable_bfd):
    return {
        "admin-state": "enable",
        "interface-type": "point-to-point",
        "failure-detection": {"enable-bfd": enable_bfd},
    }


def isis_intf(enable_bfd):
    return {
        "admin-state": "enable",
        "ipv4-unicast": {"admin-state": "disable"},
        "ipv6-unicast": {"admin-state": "enable", "enable-bfd": enable_bfd},
    }


# bfd enabled at ebgp group level
def ebgp_intf(peer_as, description):
    return {
        "admin-state": "enable",
        "peer-group": "ebgp-peers",
        "peer-as": peer_as,
        "description": description,
    }
