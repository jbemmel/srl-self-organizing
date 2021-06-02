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
import subprocess # JvB for git pull call
import traceback

import sdk_service_pb2
import sdk_service_pb2_grpc
import lldp_service_pb2
import config_service_pb2
import sdk_common_pb2
from logging.handlers import RotatingFileHandler

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
pushed_routes = 0

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
                    state.role = data['role']
                    logging.info(f"Got role :: {state.role}")
                if 'peerlinks_prefix' in data:
                    state.peerlinks_prefix = data['peerlinks_prefix']['value']
                    state.peerlinks = list(ipaddress.ip_network(data['peerlinks_prefix']['value']).subnets(new_prefix=31))
                if 'loopbacks_prefix' in data:
                    state.loopbacks = list(ipaddress.ip_network(data['loopbacks_prefix']['value']).subnets(new_prefix=32))
                if 'base_as' in data:
                    state.base_as = int( data['base_as']['value'] )
                if 'max_spines' in data:
                    state.max_spines = int( data['max_spines']['value'] )
                if 'max_leaves' in data:
                    state.max_leaves = int( data['max_leaves']['value'] )
                if 'max_hosts_per_leaf' in data:
                    state.max_hosts_per_leaf = int( data['max_hosts_per_leaf']['value'] )
                return not state.role is None

    elif obj.HasField('lldp_neighbor') and not state.role is None:
        # Update the config based on LLDP info, if needed
        logging.info(f"process LLDP notification : {obj}")
        my_port = obj.lldp_neighbor.key.interface_name  # ethernet-1/x
        to_port = obj.lldp_neighbor.data.port_id
        peer_sys_name = obj.lldp_neighbor.data.system_name

        if my_port != 'mgmt0' and to_port != 'mgmt0' and hasattr(state,'peerlinks'):
          my_port_id = re.split("/",re.split("-",my_port)[1])[1]
          m = re.match("^ethernet-(\d+)/(\d+)$", to_port)
          if m:
            to_port_id = m.groups()[1]
          else:
            to_port_id = my_port_id  # FRR Linux host or other element not sending port name

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
            _i = 0 if state.role == 'ROLE_spine' else 1 if state.role == 'ROLE_leaf' else 2
            state.router_id = f"1.1.{ _i }.{ state.node_id }"
            router_id_changed = True

          configure_peer_link( state, my_port, int(my_port_id), int(to_port_id),
            peer_sys_name, obj.lldp_neighbor.data.system_description if m else 'host', router_id_changed )

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
    if state.role == "ROLE_spine":
       # TODO spine-spine link case
       return lldp_my_port
    elif state.role == "ROLE_leaf":
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

def configure_peer_link( state, intf_name, lldp_my_port, lldp_peer_port,
                         lldp_peer_name, lldp_peer_desc, set_router_id=False ):
  # For spine-spine connections, build iBGP
  if (state.role == 'ROLE_spine') and 'spine' not in lldp_peer_name:
    _r = 0
    _i = 0
    link_index = state.max_spines * (lldp_peer_port - 1) + lldp_my_port - 1
    peer_type = 'leaf'
    _as = state.base_as
  elif (state.role != 'ROLE_endpoint'):
    logging.info(f"Configure LEAF or SPINE-SPINE local_port={lldp_my_port} peer_port={lldp_peer_port}")
    spineId = re.match(".*spine(\d+).*", lldp_peer_name)
    _masterSpine = state.role == 'ROLE_spine' and spineId and int(spineId.groups()[0]) > lldp_my_port
    _r = 0 if _masterSpine or (not spineId and state.role=='ROLE_leaf') else 1
    _i = 1
    _as = state.base_as + (0 if state.role == 'ROLE_spine' else state.node_id)
    if spineId: # For spine facing links, pick based on peer_port
      link_index = state.max_spines * (lldp_my_port - 1) + lldp_peer_port - 1
      peer_type = 'spine'
    else: # XXX hardcoded max hosts per leaf: 32
      link_index = state.max_spines * state.max_leaves + state.max_hosts_per_leaf * (state.node_id-1) + (lldp_my_port - 1)
      peer_type = 'host'
  else:
    _r = 1
    _i = 2
    peer_type = 'leaf'
    leafId = re.match(".*leaf(\d+).*", lldp_peer_name)
    if leafId:
      leaf = leafId.groups()[0] # typically 1,2,3,...
      link_index = state.max_spines * state.max_leaves + state.max_hosts_per_leaf * (int(leaf)-1) + (lldp_peer_port - 1)
      _as = state.base_as + int(leaf) # iBGP, same AS as leaf
    else: # Only supports hosts connected to different ports of leaves
      link_index = state.max_spines * state.max_leaves + (lldp_peer_port - 1)
      _as = state.base_as + lldp_peer_port

  if link_index >= len(state.peerlinks):
      logging.error(f'Out of IP peering link addresses: {link_index} >= {len(state.peerlinks)}')
      return False

  # Configure IP on interface and BGP for leaves
  link_name = f"link{link_index}"
  if not hasattr(state,link_name):
     _ip = str( list(state.peerlinks[link_index].hosts())[_r] )
     _peer = str( list(state.peerlinks[link_index].hosts())[1-_r] )
     script_update_interface(
         state.role[5:], # strip 'ROLE_' prefix
         intf_name,
         _ip + '/31',
         lldp_peer_desc,
         _peer if state.role != 'ROLE_spine' else '*',
         _as,
         state.router_id if set_router_id else "",
         state.base_as if (state.role != 'ROLE_spine') else state.base_as + 1,
         state.base_as if (state.role != 'ROLE_spine') else state.base_as + state.max_leaves,
         state.peerlinks_prefix, peer_type, "disable" # Disable OSPFv3 for now
     )
     setattr( state, link_name, _ip )


##################################################################################################
## This functions get the app_id from idb for a given app_name
##################################################################################################
def get_app_id(app_name):
    logging.info(f'Metadata {metadata} ')
    appId_req = sdk_service_pb2.AppIdRequest(name=app_name)
    app_id_response=stub.GetAppId(request=appId_req, metadata=metadata)
    logging.info(f'app_id_response {app_id_response.status} {app_id_response.id} ')
    return app_id_response.id

###########################
# JvB: Invokes gnmic client to update interface configuration, via bash script
###########################
def script_update_interface(role,name,ip,peer,peer_ip,_as,router_id,peer_as_min,peer_as_max,peer_links,peer_type,ospf):
    logging.info(f'Calling update script: role={role} name={name} ip={ip} peer_ip={peer_ip} peer={peer} as={_as} ' +
                 f'router_id={router_id} peer_links={peer_links} peer_type={peer_type} ospf={ospf}' )
    try:
       script_proc = subprocess.Popen(['/etc/opt/srlinux/appmgr/gnmic-configure-interface.sh',
                                       role,name,ip,peer,peer_ip,str(_as),router_id,
                                       str(peer_as_min),str(peer_as_max),peer_links,peer_type,ospf],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       stdoutput, stderroutput = script_proc.communicate()
       logging.info(f'script_update_interface result: {stdoutput} err={stderroutput}')
    except Exception as e:
       logging.error(f'Exception caught in script_update_interface :: {e}')

class State(object):
    def __init__(self):
        self.role = None        # May not be set in config
        self.pending_peers = {} # LLDP data received before we can determine ID

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

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

    app_id = get_app_id(agent_name)
    if not app_id:
        logging.error(f'idb does not have the appId for {agent_name} : {app_id}')
    else:
        logging.info(f'Got appId {app_id} for {agent_name}')

    request=sdk_service_pb2.NotificationRegisterRequest(op=sdk_service_pb2.NotificationRegisterRequest.Create)
    create_subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    stream_id = create_subscription_response.stream_id
    logging.info(f"Create subscription response received. stream_id : {stream_id}")

    Subscribe_Notifications(stream_id)

    stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
    stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

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
                    logging.info(f'Updated state: {state}')

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
        logging.error(f'Exception caught :: {e}')
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
    logging.info("Caught signal :: {}\n will unregister fib_agent".format(signum))
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.error('try: Unregister response:: {}'.format(response))
        sys.exit()
    except grpc._channel._Rendezvous as err:
        logging.info('GOING TO EXIT NOW: {}'.format(err))
        sys.exit()

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/<dutName>_fibagent.log
## Signals handled for graceful exit: SIGTERM
##################################################################################################
if __name__ == '__main__':
    # hostname = socket.gethostname()
    stdout_dir = '/var/log/srlinux/stdout' # PyTEnv.SRL_STDOUT_DIR
    signal.signal(signal.SIGTERM, Exit_Gracefully)
    if not os.path.exists(stdout_dir):
        os.makedirs(stdout_dir, exist_ok=True)
    log_filename = '{}/auto_config_agent.log'.format(stdout_dir)
    logging.basicConfig(filename=log_filename, filemode='a',\
                        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',\
                        datefmt='%H:%M:%S', level=logging.INFO)
    handler = RotatingFileHandler(log_filename, maxBytes=3000000,backupCount=5)
    logging.getLogger().addHandler(handler)
    logging.info("START TIME :: {}".format(datetime.datetime.now()))
    if Run():
        logging.info('Agent unregistered and agent routes withdrawed from dut')
    else:
        logging.info('Should not happen')
