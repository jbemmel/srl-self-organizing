# Use case: Adding a L3 link for extra capacity

Data centers evolve over time, and at some point capacity may need to be extended.
With traditional network LAGs this is a matter of adding a link to the bundle, but the chipsets that some SR Linux platforms use do not support
network LAGs in combination with VXLAN.

Using an auto-config agent, adding capacity becomes as easy as adding a link to a LAG:

1. Start the lab
```
sudo clab deploy -t setup.clos02.clab.yml --reconfigure
```

2. Add a link
```
sudo clab tools veth create -a clab-clos02-leaf1:e1-4 -b clab-clos02-spine1:e1-4
```

3. Enable the new link in both nodes
```
ssh admin@clab-clos02-leaf1
enter candidate
/interface ethernet-1/4 admin-state enable
commit stay
```

4. Logout of the CLI to see configuration changes
```
A:spine-1-1.1.1.1# /network-instance default protocols ospf
--{ + running }--[ network-instance default protocols ospf ]--
A:spine-1-1.1.1.1# info
    instance main {
        admin-state enable
        version ospf-v3
        address-family ipv4-unicast
        router-id 1.1.1.1
        max-ecmp-paths 8
        export-policy accept-all
        asbr {
            !!! Redistribute indirect routes including static routes
        }
        area 0.0.0.0 {
            interface ethernet-1/1.0 {
                admin-state enable
                interface-type point-to-point
                failure-detection {
                    enable-bfd true
                }
            }
            interface ethernet-1/2.0 {
                admin-state enable
                interface-type point-to-point
                failure-detection {
                    enable-bfd true
                }
            }
            interface ethernet-1/3.0 {
                admin-state enable
                interface-type point-to-point
                failure-detection {
                    enable-bfd true
                }
            }
            interface ethernet-1/4.0 { !!! Newly added
                admin-state enable
                interface-type point-to-point
                failure-detection {
                    enable-bfd true
                }
            }
            interface lo0.0 {
                admin-state enable
                passive true
            }
        }
    }
```
