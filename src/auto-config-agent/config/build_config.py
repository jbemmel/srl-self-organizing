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
