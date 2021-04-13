#!/bin/bash
###########################################################################
# Description:
#     This script will launch the python script of auto_config_agent
#     (forwarding any arguments passed to this script).
#
# Copyright (c) 2018-2021 Nokia
###########################################################################


_term (){
    echo "Caugth signal SIGTERM !! "
    kill -TERM "$child" 2>/dev/null
}

function main()
{
    trap _term SIGTERM
    local virtual_env="/opt/srlinux/python/virtual-env/bin/activate"
    local main_module="/etc/opt/srlinux/appmgr/auto-config-agent.py"

    # source the virtual-environment, which is used to ensure the correct python packages are installed,
    # and the correct python version is used
    source "${virtual_env}"
    export  PYTHONPATH="$PYTHONPATH:/etc/opt/srlinux/appmgr/:/opt/srlinux/bin:/opt/rh/rh-python36/root/usr/lib/python3.6/site-packages/sdk_protos"

    export http_proxy=""
    export https_proxy=""
    export no_proxy=""
    python3 ${main_module} &

    child=$! 
    wait "$child"

}

main "$@"
