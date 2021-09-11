#!/usr/bin/env python
# coding=utf-8

import grpc
import datetime
import sys
import logging
import socket
import os
import re
import ipaddress
import json
import signal
import subprocess
import traceback

import sdk_service_pb2
import sdk_service_pb2_grpc
import lldp_service_pb2
import config_service_pb2
import sdk_common_pb2

from logging.handlers import RotatingFileHandler

# To report state back
import telemetry_service_pb2
import telemetry_service_pb2_grpc

# Local gNMI connection
from pygnmi.client import gNMIclient, telemetryParser

############################################################
## Agent will start with this name
############################################################
agent_name='auto_config_agent'

############################################################
## Open a GRPC channel to connect to sdk_mgr on the dut
## sdk_mgr will be listening on 50053
############################################################
#channel = grpc.insecure_channel('unix:///opt/srlinux/var/run/sr_sdk_service_manager:50053')
channel = grpc.insecure_channel('127.0.0.1:50053')
metadata = [('agent_name', agent_name)]
stub = sdk_service_pb2_grpc.SdkMgrServiceStub(channel)

# Requires Unix socket to be enabled in config
# gnmi = gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
#                  username="admin",password="admin",insecure=True)

############################################################
## Subscribe to required event
## This proc handles subscription of: Interface, LLDP,
##                      Route, Network Instance, Config
############################################################
def Subscribe(stream_id, option):
    op = sdk_service_pb2.NotificationRegisterRequest.AddSubscription
    if option == 'lldp':
        entry = lldp_service_pb2.LldpNeighborSubscriptionRequest()
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, lldp_neighbor=entry)
    elif option == 'cfg':
        entry = config_service_pb2.ConfigSubscriptionRequest()
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, config=entry)

    subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    print('Status of subscription response for {}:: {}'.format(option, subscription_response.status))

############################################################
## Subscribe to all the events that Agent needs
############################################################
def Subscribe_Notifications(stream_id):
    '''
    Agent will receive notifications to what is subscribed here.
    '''
    if not stream_id:
        logging.info("Stream ID not sent.")
        return False

    # Subscribe to config changes, first
    Subscribe(stream_id, 'cfg')

    ##Subscribe to LLDP Neighbor Notifications
    ## Subscribe(stream_id, 'lldp')

############################################################
## Function to populate state of agent config
## using telemetry -- add/update info from state
############################################################
def Add_Telemetry(js_path, js_data):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_update_request = telemetry_service_pb2.TelemetryUpdateRequest()
    telemetry_info = telemetry_update_request.state.add()
    telemetry_info.key.js_path = js_path
    telemetry_info.data.json_content = js_data
    logging.info(f"Telemetry_Update_Request :: {telemetry_update_request}")
    telemetry_response = telemetry_stub.TelemetryAddOrUpdate(request=telemetry_update_request, metadata=metadata)
    return telemetry_response

############################################################
## Function to populate state fields of the agent
## It updates command: info from state auto-config-agent
############################################################
def Update_Peer_State(leaf_ip, port, lldp_peer_name):
    _ip_key = '.'.join([i.zfill(3) for i in leaf_ip.split('.')]) # sortable
    js_path = '.' + agent_name + '.leaf{.leaf_id=="' + _ip_key + '"}.lldp.port{.port_name=="'+port+'"}.neighbor'
    value = { "host_name" : { "value": lldp_peer_name } }
    response = Add_Telemetry( js_path=js_path, js_data=json.dumps(value) )
    logging.info(f"Telemetry_Update_Response :: {response}")

def Add_Discovered_Node(state, leaf_ip, port, lldp_peer_name):
    logging.info(f"Add_Discovered_Node :: {leaf_ip}:{port}={lldp_peer_name}")
    Update_Peer_State(leaf_ip, port, lldp_peer_name)
    if lldp_peer_name in state.lag_state:
        cur = state.lag_state[ lldp_peer_name ]
        cur[leaf_ip] = port # XXX only supports 1 lag link per leaf
        if state.router_id in cur and len(cur) >= 2:
            Convert_lag_to_mc_lag( state, port, leaf_ip, port ) # XXX port nok
    else:
        state.lag_state[ lldp_peer_name ] = { leaf_ip: port }

#
# Encodes the peer MAC address discovered through LLDP as a RFC8092 large community
# A:B:C where A is the access port and B,C each include 3 bytes (hex)
#
# Spine AS is included in the Route Target, so matches are scoped to cluster
#
# TODO could signal lag parameters (LACP or not, etc.) for consistency check
# Could also use different RT for each (implies same lag type for all per switch)
#
def Create_Ext_Community(state,chassis_mac,port):
    logging.info(f"Create_Ext_Community :: {port}={chassis_mac}")
    bytes = chassis_mac.split(':')
    c_b = ''.join( bytes[0:3] )
    c_c = ''.join( bytes[3:6] )
    # marker = "origin:65537:0" # Well-known LLDP event community, static. Needed?

    lldp_community = f"{int(c_b,16)}:{int(c_c,16)}"
    value = { "member": [ f"{port}:" + lldp_community ] }

    # Save locally too, excluding port
    state.lldp_communities[ lldp_community ] = port

    updates = [('/routing-policy/community-set[name=LLDP]',value)]
    deletes = []
    if state.evpn_auto_lags:
     # Toggle a special IP address on lo0.1 to trigger route count updates
     ip99 = '99.99.99.99/32'
     ip_path = '/interface[name=lo0]/subinterface[index=1]/ipv4/address'

     if not hasattr(state,'toggle_route_update') or not state.toggle_route_update:
        state.toggle_route_update = True
        updates.append( (ip_path, { 'ip-prefix': '99.99.99.99/32' } ) )
     else:
        state.toggle_route_update = False
        deletes = [ ip_path + f"[ip-prefix={ip99}]" ]
     logging.info( f"EVPN auto-lags: update={updates} delete={deletes}" )

    with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                      username="admin",password="admin",insecure=True) as c:
       c.set( encoding='json_ietf', update=updates, delete=deletes )

# Upon changes in EVPN route counts, check for updated LAG communities
from threading import Thread
class EVPNRouteMonitoringThread(Thread):
   def __init__(self,state):
       Thread.__init__(self)
       self.state = state

   def run(self):
    subscribe = {
      'subscription': [
          {
              'path': '/network-instance[name=default]/protocols/bgp/evpn',
              'mode': 'on_change'
          }
      ],
      'use_aliases': False,
      # 'updates_only': True, # Optional
      'mode': 'stream',
      'encoding': 'json'
    }
    with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                          username="admin",password="admin",
                          insecure=True, debug=False) as c:

      CreateEVPNCommunicationVRF( self.state, c )

      telemetry_stream = c.subscribe(subscribe=subscribe)
      for m in telemetry_stream:
        if m.HasField('update'): # both update and delete events
            # Filter out only toplevel events
            parsed = telemetryParser(m)
            logging.info(f"gNMI change event :: {parsed}")
            update = parsed['update']
            if update['update']:
                logging.info( f"Update: {update['update']}")

                # Assume routes changed, get attributes.
                # XXX assumes port 1 is not an access port, VXLAN interface ID would overlap
                p = "/network-instance[name=default]/bgp-rib/evpn/rib-in-out/rib-in-post/ip-prefix-routes[ip-prefix-length=32][route-distinguisher=*:1]/attr-id"
                data = c.get(path=[p], encoding='json_ietf')
                logging.info( f"Attribute set IDs: {data}" )
                for n in data['notification']:
                   if 'update' in n: # Update is empty when path is invalid
                     for u2 in n['update']:
                        logging.info( f"Update {u2['path']}={u2['val']}" )
                        for route in u2['val']['ip-prefix-routes']:
                          attr_id = route['attr-id']
                          peer_id = route['ip-prefix'].split('/')[0] # /32 loopback IP

                          p2 = f"/network-instance[name=default]/bgp-rib/attr-sets/attr-set[index={attr_id}]/communities/large-community"
                          comms = c.get(path=[p2], encoding='json_ietf')
                          logging.info( f"Communities: {comms}" )
                          for n2 in comms['notification']:
                           if 'update' in n2: # Update is empty when path is invalid
                             for u3 in n2['update']:
                                logging.info( f"Update {u3['path']}={u3['val']}" )
                                lldp_ports = u3['val']['attr-set'][0]['communities']['large-community']
                                logging.info( f"LLDP Communities from {peer_id}: {sorted(lldp_ports)}" )
                                for p in lldp_ports:
                                    parts = p.split(':')
                                    key = parts[1] + ':' + parts[2]
                                    if key in self.state.lldp_communities:
                                        lag_port = self.state.lldp_communities[ key ]
                                        logging.info( f"Found MC-LAG port match: {lag_port} peer={peer_id}" )
                                        try:
                                           # This repeatedly provisions the same thing...
                                           Convert_lag_to_mc_lag( self.state, lag_port, peer_id, parts[0] )
                                        except Exception as ex:
                                           logging.error( f"BUG: {ex}" )

    logging.info("Leaving gNMI subscribe loop")

############################################################
## Function to populate state of agent config
## using telemetry -- add/update info from state
############################################################
def Set_LLDP_Systemname(name):
   logging.info(f"Set_LLDP_Systemname :: name={name}")
   value = { "host-name" : name }
   with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                     username="admin",password="admin",insecure=True) as c:
      c.set( encoding='json_ietf', update=[('/system/name',value)] )

def Set_Default_Systemname(state):
    Set_LLDP_Systemname( f"{state.get_role()}-{state.node_id}-{state.router_id}" )

# Only used on LEAVES when auto_lags==True
def Announce_LLDP_peer(state,name,port):
    logging.info(f"Announce_LLDP_peer :: name={name} port={port} ann={state.announcing}")

    # Need to filter out duplicate events, happens rarely but does occur
    if port in state.announced and state.announced[port] == name:
        logging.info("Filtering out duplicate LLDP event")
        return
    state.announced[port] = name

    if not re.match( r"^(\d+[.]\d+[.]\d+[.]\d+)-(\d+)-(.*)$", name ):
      if (state.announcing):
        state.pending_announcements.append( (name,port) )
      else:
        state.announcing = f"{state.router_id}-{port}-{name}"
        Set_LLDP_Systemname( state.announcing )

def HandleLLDPChange(state,peername,my_port,their_port):
    # XXX assumes port=single digit, only ethernet-1/x
    m = re.match( r"^(?:spine-)?(\d+[.]\d+[.]\d+[.]\d+)-(\d+)-(.*)$", peername )
    if m:
        peer_ip = m.groups()[0]
        peer_if = m.groups()[1]
        peer_hostnode = m.groups()[2]
        logging.info(f"HandleLLDPChange :: on={my_port} leaf={peer_ip}:{peer_if} name={peername} ann={state.announcing}")

        # XXX should wait for ALL spines to ACK?
        if ("spine-" + str(state.announcing)) == peername: # Only happens for LEAVES
            Add_Discovered_Node( state, peer_ip, peer_if, peer_hostnode )
            if state.pending_announcements!=[]:
                name, port = state.pending_announcements.pop(0)
                logging.info(f"Announce_next_LLDP_peer :: name={name} port={port}")
                state.announcing = f"{state.router_id}-{port}-{name}"
                Set_LLDP_Systemname( state.announcing )
            else:
                logging.info("LEAF: No more pending announcements")
                state.announcing = ""
                Set_Default_Systemname( state )
        else:
            # Peer announcement, pass it on as spine
            if state.is_spine():
               peername = "spine-" + peername # For node_id calc on auto leaves
               if state.announcing!="" and state.announcing != my_port:
                   state.pending_announcements.append( (my_port,peername) )
               else:
                   state.announcing = my_port
                   Set_LLDP_Systemname( peername )
            else:
               # To avoid deadlock on spine, re-announce if match
               if state.announcing == "" and peer_ip == state.router_id:
                  logging.info(f"LEAF ACK {peername} on {my_port}")
                  state.announcing = peername.replace( "spine", "ACK" )
                  Set_LLDP_Systemname( state.announcing )

               Add_Discovered_Node( state, peer_ip, peer_if, peer_hostnode )

    else:
        logging.info(f"HandleLLDPChange :: no match on={my_port} name={peername} ann={state.announcing} pending={state.pending_announcements}")
        if state.is_spine():
            if state.announcing==my_port:
               logging.info( f"TODO check if not ACK, or ACK matching our systemname: {peername}" )
               if state.pending_announcements!=[]:
                   next_port, nextpeer = state.pending_announcements.pop(0)
                   state.announcing = next_port
                   Set_LLDP_Systemname(nextpeer)
               else:
                   state.announcing = ""
                   Set_Default_Systemname(state)
        elif re.match( "^ACK-.*", state.announcing ): # For leaves
            state.announcing = ""
            Set_Default_Systemname(state)

    return False

###
# Converts an ethernet interface to a lag, creating a mac-vrf, irb,
# optional: bgp-evpn l2 vni, ethernet segment with ESI
##
def Convert_to_lag(state,port,ip,vrf="overlay"):
   logging.info(f"Convert_to_lag :: port={port} ip={ip} vrf={vrf}")
   eth = f'name=ethernet-1/{port}'
   deletes=[ f'/network-instance[name={vrf}]/interface[{eth}.0]',
             f'/interface[{eth}]/subinterface[index=*]',
             f'/interface[{eth}]/vlan-tagging' ]
   lag = {
      "admin-state": "enable",
      "srl_nokia-interfaces-vlans:vlan-tagging": True,
      "subinterface": [
       {
         "index": 0,
         "type": "srl_nokia-interfaces:bridged",
         "srl_nokia-interfaces-vlans:vlan": {
           # "encap": { "single-tagged": { "vlan-id": 1 } }
           "encap": { "untagged": { } }
         }
       }
      ],
      "srl_nokia-interfaces-lag:lag": {
       "lag-type": "static",
       "member-speed": "25G"
      }
   }

   irb_if = {
    "admin-state": "enable",
    "subinterface": [
    {
      "index": int(port),
      "admin-state": "enable",
      "ipv4": {
        "address": [
          {
            "ip-prefix": ip, # /31 link IP (or .1 out of /24-30)
            "primary": '[null]'  # type 'empty', used as source for bcast
          }
        ]
      },
      "anycast-gw": {}
    }
    ]
   }
   if state.host_enable_ipv6:
       # TODO could add ipv6 link IP too
       irb_if['subinterface'][0]['ipv6'] = { }

   if hasattr(state,'anycast_gw'):
       irb_if['subinterface'][0]['ipv4']['address'].append( {
         "ip-prefix": state.anycast_gw,
         "anycast-gw": True
       } )

   # EVPN VXLAN interface
   vxlan_if = {
      "type": "srl_nokia-interfaces:bridged",
      "ingress": { "vni": int(port) },
      "egress": { "source-ip": "use-system-ipv4-address" }
   }

   # Could configure MAC table size here
   mac_vrf = {
     "type": "srl_nokia-network-instance:mac-vrf",
     "admin-state": "enable",
     "interface": [ { "name": f"lag{port}.0" }, { "name" : f"irb0.{port}" } ],
   }
   if state.evpn != 'disabled':
      rt = f"target:{state.base_as}:{port}"

      # Not currently used
      export_policy = {
        "community-set": [ { "name": f"LAG{port}", "member": [ rt ], } ],
        "policy": [
        {
         "name": f"add-rt-{state.base_as}-{port}",
         "statement": [
          {
           "sequence-id": 10,
           "action": {
            "accept": { "bgp": { "communities": { "add": f"LAG{port}" } } }
           }
          }
         ]
        }]
      }

      mac_vrf.update(
      {
        "vxlan-interface": [ { "name": f"vxlan0.{port}" } ],
        "protocols": {
         "bgp-evpn": {
          "srl_nokia-bgp-evpn:bgp-instance": [
           {
             "id": 1,
             "admin-state": "enable",
             "vxlan-interface": f"vxlan0.{port}",
             "evi": int(port),
             "ecmp": 8
           }
          ]
         },
         "srl_nokia-bgp-vpn:bgp-vpn": {
           "bgp-instance": [
            { "id": 1,
              # "export-policy": f"add-rt-{state.base_as}-{port}",
              "route-target": {
               "_annotate": "Need to specify explicitly, each leaf has a different AS so auto-RT won't work",
               "export-rt": rt,
               "import-rt": rt
              }
            }
           ]
         }
        }
      })

   updates=[ (f'/interface[name=lag{port}]',lag),
             (f'/interface[name=irb0]', irb_if),
             (f'/interface[{eth}]/ethernet',{ 'aggregate-id' : f'lag{port}' } ),
             (f'/network-instance[name=lag{port}]', mac_vrf),
             (f'/network-instance[name={vrf}]/interface[name=irb0.{port}]', {}),
           ]
   if state.evpn != 'disabled':
       updates += [
         (f'/tunnel-interface[name=vxlan0]/vxlan-interface[index={port}]', vxlan_if ),
         # ('/routing-policy', export_policy)
       ]

   logging.info(f"gNMI SET deletes={deletes} updates={updates}" )
   with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                     username="admin",password="admin",insecure=True) as c:
      c.set( encoding='json_ietf', delete=deletes, update=updates )

#
# Called when an EVPN community match is discovered
# Assumes lag is already created
#
def Convert_lag_to_mc_lag(state,port,peer_leaf,peer_port):
   logging.info(f"Convert_lag_to_mc_lag :: port={port} peer_leaf={peer_leaf} peer_port={peer_port}")

   if port in state.mc_lags:
      state.mc_lags[port].update( { peer_leaf : peer_port } )
   else:
      state.mc_lags[port] = { peer_leaf : peer_port }

   if len( state.mc_lags[port] ) > 3:
       logging.error( "Platform does not support MC-LAG with more than 4 members" )
       return False

   peers = str( sorted( state.mc_lags[port].items() ) )

   # EVPN MC-LAG
   sys_bgp_evpn = {
    "bgp-vpn": { "bgp-instance": [ { "id": 1 } ] },
    "evpn": {
     "ethernet-segments": {
      "bgp-instance": [
        {
          "id": 1,
          "ethernet-segment": [
            {
              "name": f"mc-lag{port}",
              "admin-state": "enable",
              "esi": f"00:12:12:12:12:12:12:00:00:{int(port):02x}",
              "_annotate_esi": f"EVPN MC-LAG with {peers}",
              "interface": f"lag{port}",
              "multi-homing-mode": "all-active"
            }
          ]
        }
      ]
     }
    }
   }

   # Update IRB interface to learn unsolicited ARPs
   # Based on 8.1.1 p72 in https://documentation.nokia.com/cgi-bin/dbaccessfilename.cgi/3HE16831AAAATQZZA01_V1_SR%20Linux%20R21.3%20EVPN-VXLAN%20User%20Guide.pdf
   url = "https://documentation.nokia.com/cgi-bin/dbaccessfilename.cgi/3HE16831AAAATQZZA01_V1_SR%20Linux%20R21.3%20EVPN-VXLAN%20User%20Guide.pdf"
   arp = {
      "learn-unsolicited": True,
      "_annotate_learn-unsolicited": f"To support MC-LAG, see {url} p72",
      "evpn": { "advertise": [ {
        "route-type": "dynamic",
        "_annotate": "for ARP synchronization across MH leaf nodes"
      } ] }
   }

   updates = [
     ('/system/network-instance/protocols', sys_bgp_evpn ),
     (f'/interface[name=irb0]/subinterface[index={port}]/ipv4/arp', arp)
   ]

   logging.info(f"gNMI SET updates={updates}" )
   with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                     username="admin",password="admin",insecure=True) as c:
      c.set( encoding='json_ietf', update=updates )

###
# Configures the default network instance to use BGP unnumbered between
# spines and leaves, using FRR agent https://github.com/jbemmel/srl-frr-agent
##
def Configure_BGP_unnumbered(router_id,local_as,port):
   logging.info(f"Configure_BGP_unnumbered :: port={port}")
   eth = f'name=ethernet-1/{port}'

   # This gets updated every time an interface is added
   frr = {
    "admin-state": "enable",
    "router-id" : router_id,
    "autonomous-system" : local_as,
    "bgp" : {
     "admin-state": "enable",
    }
   }

   # BGP unnumbered interfaces must have ipv4 and ipv6 enabled, now handled
   # by FRR agent itself

   bgp_u = { "bgp-unnumbered-peer-as": "external" }
   updates=[ (f'/network-instance[name=default]/protocols/experimental-frr', frr),
             (f'/network-instance[name=default]/interface[{eth}.0]', bgp_u ),
           ]
   logging.info(f"gNMI SET updates={updates}" )
   with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                     username="admin",password="admin",insecure=True) as c:
      c.set( encoding='json_ietf', update=updates )

#
# Creates a special IP-VRF to announce a loopback RT5 route with extended
# communities based on discovered LLDP peers (MAC addresses)
#
def CreateEVPNCommunicationVRF(state,gnmiClient):
   logging.info("CreateEVPNCommunicationVRF")

   lo0_1_if = {
    "admin-state": "enable",
    "subinterface": [
     {
      "index": 1,
      "admin-state": "enable",
      "ipv4": {
        "address": [
          {
            "ip-prefix": state.router_id + '/32',
          }
        ]
      }
     }
    ]
   }

   # Routed VXLAN interface
   vxlan_if = {
      "type": "srl_nokia-interfaces:routed",
      "ingress": { "vni": 1 },
      "egress": { "source-ip": "use-system-ipv4-address" }
   }

   policy_name = "export-lldp-communities-for-mc-lag-discovery"
   lldp_rt = f"target:{state.base_as}:1" # RT for the cluster AS
   lldp_export_policy = {
     "community-set": [ { "name": "LLDP", "member": [ lldp_rt ], } ],
     "policy": [
      {
       "name": policy_name,
       "default-action": {
         "accept": { "bgp": { "communities": { "add": "LLDP" } } }
       }
      }
     ]
   }

   ip_vrf = {
     "type": "srl_nokia-network-instance:ip-vrf",
     "admin-state": "enable",
     "interface": [ { "name": "lo0.1" } ],
     "vxlan-interface": [ { "name": "vxlan0.1" } ],
     "protocols": {
      "bgp-evpn": {
       "srl_nokia-bgp-evpn:bgp-instance": [
        {
          "id": 1,
          "admin-state": "enable",
          "vxlan-interface": "vxlan0.1",
          "evi": 1, # auto-RD == <router-ID>:1
        }
       ]
      },
      "srl_nokia-bgp-vpn:bgp-vpn": {
        "bgp-instance": [
         { "id": 1,
           "export-policy": policy_name,
           "route-target": {
            "_annotate": "Special RT for EVPN LAG coordination",
            "import-rt": lldp_rt
           }
            }
           ]
         }
     }
   }

   updates=[ (f'/interface[name=lo0]', lo0_1_if),
             (f'/tunnel-interface[name=vxlan0]/vxlan-interface[index=1]', vxlan_if ),
             ('/routing-policy', lldp_export_policy),
             (f'/network-instance[name=evpn-lag-discovery]', ip_vrf),
           ]

   logging.info(f"gNMI SET updates={updates}" )
   gnmiClient.set( encoding='json_ietf', update=updates )

##################################################################
## Proc to process the config Notifications received by auto_config_agent
## At present processing config from js_path = .fib-agent
##################################################################
def Handle_Notification(obj, state):
    if obj.HasField('config') and obj.config.key.js_path != ".commit.end":
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")
        if "auto_config" in obj.config.key.js_path:
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            if obj.config.op == 2:
                logging.info(f"Delete auto-config-agent cli scenario")
                # if file_name != None:
                #    Update_Result(file_name, action='delete')
                response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
                logging.info('Handle_Config: Unregister response:: {}'.format(response))
            else:
                json_acceptable_string = obj.config.data.json.replace("'", "\"")
                data = json.loads(json_acceptable_string)
                if 'role' in data:
                    state.role = data['role'][5:] # strip "ROLE_"
                    logging.info(f"Got role :: {state.role}")
                if 'peerlinks' in data:
                    peerlinks = data['peerlinks']
                    state.peerlinks_prefix = peerlinks['prefix']['value']
                    state.peerlinks = list(ipaddress.ip_network(state.peerlinks_prefix).subnets(new_prefix=31))
                    state.hostlinks_size = int( peerlinks['host_subnet_size']['value'] )
                    state.host_enable_ipv6 = bool( peerlinks['host_enable_ipv6']['value'] )
                    state.hostlinks = list(ipaddress.ip_network(state.peerlinks_prefix).subnets(new_prefix=state.hostlinks_size))
                if 'loopbacks_prefix' in data:
                    # state.loopbacks = list(ipaddress.ip_network(data['loopbacks_prefix']['value']).subnets(new_prefix=32))
                    state.loopbacks_prefix = ipaddress.ip_network(data['loopbacks_prefix']['value'])
                if 'base_as' in data:
                    state.base_as = int( data['base_as']['value'] )
                if 'leaf_as' in data:
                    state.leaf_as = int( data['leaf_as']['value'] )
                if 'host_as' in data:
                    state.host_as = int( data['host_as']['value'] )
                if 'max_spines' in data:
                    state.max_spines = int( data['max_spines']['value'] )
                if 'max_leaves' in data:
                    state.max_leaves = int( data['max_leaves']['value'] )
                if 'max_hosts_per_leaf' in data:
                    state.max_hosts_per_leaf = int( data['max_hosts_per_leaf']['value'] )
                if 'max_lag_links' in data:
                    state.max_lag_links = int( data['max_lag_links']['value'] )
                if 'evpn' in data:
                    state.evpn = data['evpn'][5:] # strip "EVPN_"
                if 'use_ospfv3' in data:
                    state.ospfv3 = 'enable' if data['use_ospfv3']['value'] else 'disable'
                if 'use_bgp_unnumbered' in data:
                    state.use_bgp_unnumbered = data['use_bgp_unnumbered']['value']
                if 'evpn_auto_lags' in data:
                    state.evpn_auto_lags = data['evpn_auto_lags']['value'] and state.evpn!="disabled"
                if 'host_use_irb' in data:
                    state.host_use_irb = data['host_use_irb']['value']
                if 'anycast_gw' in data:
                    state.anycast_gw = data['anycast_gw']['value']

                return state.role is not None
    elif obj.HasField('lldp_neighbor') and not state.role is None:
        # Update the config based on LLDP info, if needed
        logging.info(f"process LLDP notification : {obj} op='{obj.lldp_neighbor.op}'")

        # Since 21.6 there are 'Delete' events too
        if obj.lldp_neighbor.op == 2: # Delete, class 'int'
            return False

        my_port = obj.lldp_neighbor.key.interface_name  # ethernet-1/x
        to_port = obj.lldp_neighbor.data.port_id
        peer_sys_name = obj.lldp_neighbor.data.system_name

        if my_port != 'mgmt0' and to_port != 'mgmt0' and hasattr(state,'peerlinks'):
          my_port_id = re.split("/",re.split("-",my_port)[1])[1]
          m = re.match("^ethernet-(\d+)/(\d+)$", to_port)
          # Allow SRL-based emulated hosts called h1, h2...
          if m and not re.match("^h[0-9]+", peer_sys_name):
            to_port_id = m.groups()[1]
          else:
            to_port_id = my_port_id  # FRR Linux host or other element not sending port name
            if not state.host_lldp_seen and state.role == 'auto':
               logging.info( "Received host LLDP (no portname match); auto switching to leaf")
               state.host_lldp_seen = True
               delattr(state,"router_id")  # Re-determine IDs
               delattr(state,"node_id")

          # First figure out this node's relative id in its group. Don't depend on hostname
          if not hasattr(state,"node_id"):
             node_id = determine_local_node_id( state, int(my_port_id), int(to_port_id), peer_sys_name)
             if node_id == 0:
                state.pending_peers[ my_port ] = ( int(my_port_id), int(to_port_id),
                  peer_sys_name, obj.lldp_neighbor.data.system_description )
                return False; # Unable to continue configuration
             state.node_id = node_id

          router_id_changed = False
          if m and not hasattr(state,"router_id"): # Only for valid to_port, if not set
            state.router_id = determine_router_id( state, state.get_role(), state.node_id )
            router_id_changed = True
            if state.role != "endpoint":
               Set_Default_Systemname( state )
               if state.get_role()=="leaf" and state.evpn_auto_lags:
                  # XXX assumes router_id wont change after this point
                  EVPNRouteMonitoringThread(state).start()

          if obj.lldp_neighbor.op == 1: # Change, class 'int'
              return HandleLLDPChange( state, peer_sys_name, my_port, to_port )

          configure_peer_link( state, my_port, int(my_port_id), int(to_port_id),
            peer_sys_name, obj.lldp_neighbor.data.system_description if m else 'host', router_id_changed )

          # Could also announce communities for spines
          if state.get_role() == "leaf" and not "spine" in peer_sys_name:
             Create_Ext_Community( state, obj.lldp_neighbor.key.chassis_id, int(my_port_id) )
          else:
             logging.info( f"Not creating LLDP Community for port {my_port_id} peer={peer_sys_name}" )

          if router_id_changed:
             for intf in state.pending_peers:
                 _my_port_id, _to_port_id, _peer_sys_name, _lldp_desc = state.pending_peers[intf]
                 configure_peer_link( state, intf, _my_port_id, _to_port_id, _peer_sys_name, _lldp_desc )

    else:
        logging.info(f"Unexpected notification : {obj}")

    # dont subscribe to LLDP now
    return False

#####
## Determine this node's local ID within its group ( e.g. leaf1 = 1, spine1 = 1 )
## Depends on LLDP system naming for now (but not local system name)
#####
def determine_local_node_id( state, lldp_my_port, lldp_peer_port, lldp_peer_name ):
   if state.is_spine():
       # TODO spine-spine link case
       return lldp_peer_port
   elif state.get_role() == "leaf":
        if "spine" in lldp_peer_name:
            return lldp_peer_port
        else:
            return 0 # Cannot determine yet
   else:
        leafId = re.match(".*leaf(\d+).*", lldp_peer_name)
        if leafId:
            # Disambiguate assuming N ports per leaf
            return (int(leafId.groups()[0]) - 1) * state.max_hosts_per_leaf + lldp_peer_port
        return lldp_peer_port

###
# Calculates an IPv4 address to be used as router ID for the given node/role
# Note: More generically 'node level', spine=0 leaf=1 host=2 for standard CLOS
###
def determine_router_id( state, role, node_id ):
    _l = node_level(role)
    return str( state.loopbacks_prefix[ 256 * _l + node_id ] )

def node_level( role ):
    if role=="spine":
        return 0
    elif role=="leaf":
        return 1
    return 2

def configure_peer_link( state, intf_name, lldp_my_port, lldp_peer_port,
                         lldp_peer_name, lldp_peer_desc, set_router_id=False ):
  # For spine-spine connections, build iBGP
  peer_router_id = ""
  if state.is_spine() and ('spine' not in lldp_peer_name):
    _r = 0
    _i = 0
    link_index = state.max_spines * (lldp_peer_port - 1) + lldp_my_port - 1
    peer_type = 'leaf'
    min_peer_as = _as = state.base_as
    max_peer_as = min_peer_as + state.max_leaves
  elif (state.role != 'endpoint'):
    logging.info(f"Configure LEAF or SPINE-SPINE local_port={lldp_my_port} peer_port={lldp_peer_port}")
    spineId = re.match(".*(?:spine)[-]?(\d+).*", lldp_peer_name)
    _masterSpine = state.get_role() == 'spine' and spineId and int(spineId.groups()[0]) > lldp_my_port
    _r = 0 if _masterSpine or (not spineId and state.get_role()=='leaf') else 1
    _i = 1
    _as = state.leaf_as if state.leaf_as!=0 else (
           state.base_as + (0 if state.get_role() == 'spine' # Use i- for iBGP
                             or 'i-' in lldp_peer_name else state.node_id))
    min_peer_as = state.base_as # Overlay AS
    max_peer_as = state.host_as if state.host_as!=0 else state.base_as
    if spineId: # For spine facing links, pick based on peer_port
      link_index = state.max_spines * (lldp_my_port - 1) + lldp_peer_port - 1
      peer_type = 'spine'
      peer_router_id = determine_router_id( state, peer_type, int(spineId.groups()[0]) )
    else:
      link_index = (lldp_my_port - 1) # Reuse underlay address space
      peer_type = 'host'

      # For access ports, announce LLDP events if auto_lags is enabled
      # if state.auto_lags:
      #     Announce_LLDP_peer( state, lldp_peer_name, lldp_my_port )

  else:
    _r = 1
    _i = 2
    _as = state.host_as if state.host_as!=0 else state.base_as # iBGP to leaves uses same AS as spines
    min_peer_as = max_peer_as = state.base_as
    peer_type = 'leaf'

    # For IP addressing, reuse same link space as underlay, purely by leaf port
    # TODO lag addressing is different
    link_index = (lldp_peer_port - 1)

  if link_index >= len(state.peerlinks):
      logging.error(f'Out of IP peering link addresses: {link_index} >= {len(state.peerlinks)}')
      return False

  # Configure IP on interface and BGP for leaves
  # Reuse link IPs between overlay and underlay
  link_name = f"link{link_index}-{peer_type}"
  if not hasattr(state,link_name):
     if not state.use_bgp_unnumbered or peer_type=='host':
       if peer_type!='host' or state.hostlinks_size == 31:
         _ip = str( list(state.peerlinks[link_index].hosts())[_r] ) + '/31'
         _peer = str( list(state.peerlinks[link_index].hosts())[1-_r] )
       else:
         _p = f"/{state.hostlinks_size}"
         _ip = str( list(state.hostlinks[link_index].hosts())[0] ) + _p
         _peer = str( list(state.hostlinks[link_index].hosts())[1] )
     else:
       _ip = ""
       _peer = "*"
     logging.info(f"Configuring link {link_name} local_port={lldp_my_port} peer_port={lldp_peer_port} ip={_ip}")
     script_update_interface(
         state,
         intf_name,
         _ip,
         lldp_peer_desc,
         _peer if state.get_role() != 'spine' else '*',
         _as,
         state.router_id if set_router_id else "",
         min_peer_as, # For spine, allow both iBGP (same AS) and eBGP
         max_peer_as,
         state.peerlinks_prefix,
         peer_type,
         peer_router_id
     )
     setattr( state, link_name, _ip )

     # For access ports, convert to L2 service if requested
     if peer_type=='host' and state.host_use_irb:
        Convert_to_lag( state, lldp_my_port, _ip ) # No EVPN MC-LAG yet
     else:
       logging.info( f"Not a host facing port ({peer_type}) or configured to not use IRB: {intf_name}" )

     if state.use_bgp_unnumbered:
         if (peer_type!='host' and state.get_role() != 'endpoint'):
             Configure_BGP_unnumbered( state.router_id, _as, lldp_my_port )

  else:
     logging.info(f"Link {link_name} already configured local_port={lldp_my_port} peer_port={lldp_peer_port}")

###########################
# JvB: Invokes gnmic client to update interface configuration, via bash script
###########################
def script_update_interface(state,name,ip,peer,peer_ip,_as,router_id,peer_as_min,peer_as_max,peer_links,peer_type,peer_rid):
    logging.info(f'Calling update script: role={state.get_role()} name={name} ip={ip} peer_ip={peer_ip} peer={peer} as={_as} ' +
                 f'router_id={router_id} peer_links={peer_links} peer_type={peer_type} peer_router_id={peer_rid} evpn={state.evpn} ' +
                 f'peer_as_min={peer_as_min} peer_as_max={peer_as_max}' )
    try:
       script_proc = subprocess.Popen(['scripts/gnmic-configure-interface.sh',
                                       state.get_role(),name,ip,peer,peer_ip,str(_as),router_id,
                                       str(peer_as_min),str(peer_as_max),peer_links,
                                       peer_type,peer_rid,
                                       state.ospfv3,
                                       state.evpn],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       stdoutput, stderroutput = script_proc.communicate()
       logging.info(f'script_update_interface result: {stdoutput} err={stderroutput}')
    except Exception as e:
       logging.error(f'Exception caught in script_update_interface :: {e}')

class State(object):
    def __init__(self):
        self.role = None        # May not be set in config, default 'auto'
        self.host_lldp_seen = False # To auto-detect leaves: >= 1 host connected
        self.pending_peers = {} # LLDP data received before we can determine ID

        self.announcing = ""    # Becomes Boolean for spines
        self.pending_announcements = []
        self.announced = {}     # To filter duplicate LLDP events

        self.lag_state = {}     # Used for auto-provisioning of LAGs
        self.host_use_irb = True
        self.use_bgp_unnumbered = False
        self.lldp_communities = {}
        self.mc_lags = {}

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def get_role(self):
        # TODO could return "spine" when all active ports have LLDP
        if self.role=="auto":
           return "leaf" if self.host_lldp_seen else "spine"
        else:
           return self.role

    def is_spine(self):
        return self.get_role() == "spine"

##################################################################################################
## This is the main proc where all processing for auto_config_agent starts.
## Agent registration, notification registration, Subscrition to notifications.
## Waits on the subscribed Notifications and once any config is received, handles that config
## If there are critical errors, Unregisters the fib_agent gracefully.
##################################################################################################
def Run():
    sub_stub = sdk_service_pb2_grpc.SdkNotificationServiceStub(channel)

    response = stub.AgentRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
    logging.info(f"Registration response : {response.status}")

    request=sdk_service_pb2.NotificationRegisterRequest(op=sdk_service_pb2.NotificationRegisterRequest.Create)
    create_subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    stream_id = create_subscription_response.stream_id
    logging.info(f"Create subscription response received. stream_id : {stream_id}")

    Subscribe_Notifications(stream_id)

    stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
    stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

    # TODO enable all detected interfaces through gNMI? Currently static in config

    state = State()
    count = 1
    lldp_subscribed = False
    try:
        for r in stream_response:
            logging.info(f"Count :: {count}  NOTIFICATION:: \n{r.notification}")
            count += 1
            for obj in r.notification:
                if obj.HasField('config') and obj.config.key.js_path == ".commit.end":
                    logging.info('TO DO -commit.end config')
                else:
                    if Handle_Notification(obj, state) and not lldp_subscribed:
                       Subscribe(stream_id, 'lldp')
                       lldp_subscribed = True

                    # Program router_id only when changed
                    # if state.router_id != old_router_id:
                    #   gnmic(path='/network-instance[name=default]/protocols/bgp/router-id',value=state.router_id)
                    # logging.info(f'Updated state: {state}')

    except grpc._channel._Rendezvous as err:
        logging.info(f'GOING TO EXIT NOW, DOING FINAL git pull: {err}')
        # try:
           # Need to execute this in the mgmt network namespace, hardcoded name for now
           # XXX needs username/password unless checked out using 'git:'
           # git_pull = subprocess.Popen(['/usr/sbin/ip','netns','exec','srbase-mgmt','/usr/bin/git','pull'],
           #                            cwd='/etc/opt/srlinux/appmgr',
           #                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
           # stdoutput, stderroutput = git_pull.communicate()
           # logging.info(f'git pull result: {stdoutput} err={stderroutput}')
        # except Exception as e:
        #   logging.error(f'Exception caught in git pull :: {e}')

    except Exception as e:
        traceback_str = ''.join(traceback.format_tb(e.__traceback__))
        logging.error(f'Exception caught :: {e} stack:{traceback_str}')
        # traceback.print_exc()
        #if file_name != None:
        #    Update_Result(file_name, action='delete')
        try:
            response = stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
            logging.error(f'Run try: Unregister response:: {response}')
        except grpc._channel._Rendezvous as err:
            logging.info(f'GOING TO EXIT NOW: {err}')
            sys.exit()
        return True
    sys.exit()
    return True
############################################################
## Gracefully handle SIGTERM signal
## When called, will unregister Agent and gracefully exit
############################################################
def Exit_Gracefully(signum, frame):
    logging.info("Caught signal :: {}\n will unregister auto_config_agent".format(signum))
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.error('try: Unregister response:: {}'.format(response))
        sys.exit()
    except grpc._channel._Rendezvous as err:
        logging.info('GOING TO EXIT NOW: {}'.format(err))
        sys.exit()

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/auto_config_agent.log
## Signals handled for graceful exit: SIGTERM
##################################################################################################
if __name__ == '__main__':
    # hostname = socket.gethostname()
    stdout_dir = '/var/log/srlinux/stdout' # PyTEnv.SRL_STDOUT_DIR
    signal.signal(signal.SIGTERM, Exit_Gracefully)
    if not os.path.exists(stdout_dir):
        os.makedirs(stdout_dir, exist_ok=True)
    log_filename = '{}/auto_config_agent.log'.format(stdout_dir)
    logging.basicConfig(
      handlers=[RotatingFileHandler(log_filename, maxBytes=3000000,backupCount=5)],
      format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
      datefmt='%H:%M:%S', level=logging.INFO)

    logging.info("START TIME :: {}".format(datetime.datetime.now()))
    if Run():
        logging.info('Agent unregistered')
    else:
        logging.info('Should not happen')
