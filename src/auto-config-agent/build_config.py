def routing_policy(is_leaf):
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
                "prefix": [
                    {"ip-prefix": "$LINK_PREFIX", "mask-length-range": "28..31"}
                ],
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
