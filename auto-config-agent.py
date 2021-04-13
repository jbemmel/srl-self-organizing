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

import sdk_service_pb2
import sdk_service_pb2_grpc
import lldp_service_pb2
import interface_service_pb2
import networkinstance_service_pb2
import route_service_pb2
import route_service_pb2_grpc
import nexthop_group_service_pb2
import nexthop_group_service_pb2_grpc
import mpls_service_pb2
import mpls_service_pb2_grpc
import config_service_pb2
import telemetry_service_pb2
import telemetry_service_pb2_grpc
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
    if option == 'intf':
        entry = interface_service_pb2.InterfaceSubscriptionRequest()
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, intf=entry)
    elif option == 'nw_inst':
        entry = networkinstance_service_pb2.NetworkInstanceSubscriptionRequest()
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, nw_inst=entry)
    elif option == 'lldp':
        entry = lldp_service_pb2.LldpNeighborSubscriptionRequest()
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, lldp_neighbor=entry)
    elif option == 'route':
        entry = route_service_pb2.IpRouteSubscriptionRequest()
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, route=entry)
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
    
    ##Subscribe to Interface Notifications
    # Subscribe(stream_id, 'intf')
    
    ##Subscribe to Network-Instance Notifications
    # Subscribe(stream_id, 'nw_inst')

    ##Subscribe to LLDP Neighbor Notifications
    Subscribe(stream_id, 'lldp')

    ##Subscribe to IP Route Notifications
    # Subscribe(stream_id, 'route')

############################################################
## Function to populate state of agent config 
## using telemetry -- add/update info from state 
############################################################
def Add_Telemetry(js_path, js_data ):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_update_request = telemetry_service_pb2.TelemetryUpdateRequest()
    telemetry_info = telemetry_update_request.state.add()
    telemetry_info.key.js_path = js_path
    telemetry_info.data.json_content = js_data
    logging.info(f"Telemetry_Update_Request :: {telemetry_update_request}")
    telemetry_response = telemetry_stub.TelemetryAddOrUpdate(request=telemetry_update_request, metadata=metadata)
    return telemetry_response

############################################################
## Function to cleanup state of agent config 
## using telemetry -- cleanup info from state
############################################################
def Delete_Telemetry(js_path):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_delete_request = telemetry_service_pb2.TelemetryDeleteRequest()
    telemetry_delete = telemetry_delete_request.key.add()
    telemetry_delete.js_path = js_path
    logging.info(f"Telemetry_Delete_Request :: {telemetry_delete_request}")
    telemetry_response = telemetry_stub.TelemetryDelete(request=telemetry_delete_request, metadata=metadata)
    return telemetry_response

############################################################
## Function to populate state fields of the agent
## It updates command: info from state fib-agent
############################################################
def Update_Result(input_fib, result=True, reason=None, action='add'):
    js_path = '.fib_agent.fib_result{.name=="' + input_fib + '"}'
    json_content='{"fib_result": '
    if action == 'add':
        for key in ['programmed-state', 'reason-code']:
            if key == 'programmed-state':
                json_content=json_content+ '{ "programmed_state" : {"value": ' + str(result).lower()+' },'
            else:
                if result == False:
                    code = reason
                else:
                    code = None
                json_content =json_content+  '"reason_code" : {"value": "' + str(code) +'"}'
        json_content =json_content+'}}'
        response = Add_Telemetry(js_path=js_path, js_data=json_content)
        logging.info(f"Telemetry_Update_Response :: {response}")
        return True
    elif action =='delete':
        response = Delete_Telemetry(js_path=js_path)
        logging.info(f"Telemetry_Delete_Response :: {response}")
        return True
    else:
        assert False, "Got unrecognized action"
    return True   

############################################################
## Function to populate number of route count received by agent
## It updates command: info from state fib-agent route-count
############################################################
def Update_Routes(programmed, actual=None):
    json_content = ''
    js_path = '.demo_fib_agent'
    json_content = '{"programmed_routes": {"value": ' + str(programmed) + '},'
    if actual:
        route_count = actual
    else:
        route_count = pushed_routes
    json_content = json_content + '"route_count": {"value": ' + str(route_count) + '}}'
    
    Add_Telemetry(js_path=js_path, js_data=json_content)
    return True

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
                if 'peerlinks-prefix' in data:
                    state.peerlinks = ip_network(data['peerlinks-prefix']).subnets(new_prefix=31)
                if 'loopbacks-prefix' in data:
                    state.loopbacks = ip_network(data['loopbacks-prefix']).subnets(new_prefix=32)
                 
    elif obj.HasField('lldp_neighbor'):
        # Update the config based on LLDP info, if needed
        logging.info(f"process LLDP notification : {obj}")
        my_port = obj.lldp_neighbor.key.interface_name  # ethernet-1/x
        to_port = obj.lldp_neighbor.data.port_id
        
        if my_port != 'mgmt0' and to_port != 'mgmt0':
          my_port_id = re.split("/",re.split("-",my_port)[1])[1]
          to_port_id = re.split("/",re.split("-",to_port)[1])[1]
        
          if (state.role == 'ROLE_spine'):
            _r = '0'
          else:
            _r = '1'
          state.router_id = f"1.1.{_r}.{to_port_id}"
    else:
        logging.info(f"Unexpected notification : {obj}")                        

    #always return updated state
    return state
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
# JvB: Invokes gnmic client to update node configuration
def gnmic(path,value):
    logging.info(f'Calling gnmic: path={path} value={value}')
    try:
       # Need to execute this in the mgmt network namespace, hardcoded name for now
       #git_pull = subprocess.Popen(['/usr/sbin/ip','netns','exec','srbase-mgmt','/usr/bin/git','pull'], 
       #                            cwd='/etc/opt/srlinux/appmgr',
       #                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       gnmic_proc = subprocess.Popen(['/usr/local/bin/gnmic','-a','127.0.0.1:57400','-u','admin','-p','admin',
                                      '--skip-verify','--encoding','JSON_IETF','set',
                                      '--update-path',path,'--update-value',value ], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
       stdoutput, stderroutput = gnmic_proc.communicate()
       logging.info(f'gnmic result: {stdoutput} err={stderroutput}')
    except Exception as e:
       logging.error(f'Exception caught in gnmic :: {e}')

class State(object):
    def __init__(self):
        self.router_id = None
    
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
    try:
        for r in stream_response:
            logging.info(f"Count :: {count}  NOTIFICATION:: \n{r.notification}")
            count += 1
            for obj in r.notification:
                if obj.HasField('config') and obj.config.key.js_path == ".commit.end":
                    logging.info('TO DO -commit.end config')
                else:
                    old_router_id = state.router_id
                    Handle_Notification(obj, state)
                    
                    # Program router_id only when changed
                    if state.router_id != old_router_id:
                       gnmic(path='/network-instance[name=default]/protocols/bgp/router-id',value=state.router_id)
                    logging.info(f'Updated state: {state}')

    except grpc._channel._Rendezvous as err:
        logging.info('GOING TO EXIT NOW, DOING FINAL git pull: {}'.format(err))
        try:
           # Need to execute this in the mgmt network namespace, hardcoded name for now
           git_pull = subprocess.Popen(['/usr/sbin/ip','netns','exec','srbase-mgmt','/usr/bin/git','pull'], 
                                       cwd='/etc/opt/srlinux/appmgr',
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
           stdoutput, stderroutput = git_pull.communicate()
           logging.info(f'git pull result: {stdoutput} err={stderroutput}')
        except Exception as e:
           logging.error(f'Exception caught in git pull :: {e}')

    except Exception as e:
        logging.error('Exception caught :: {}'.format(e))
        #if file_name != None:
        #    Update_Result(file_name, action='delete')
        try:
            response = stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
            logging.error('Run try: Unregister response:: {}'.format(response))
        except grpc._channel._Rendezvous as err:
            logging.info('GOING TO EXIT NOW: {}'.format(err))
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
