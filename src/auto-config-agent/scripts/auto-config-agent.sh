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
    local virtual_env="/opt/demo-agents/auto-config-agent/.venv"

    # source the virtual-environment, which is used to ensure the correct python packages are installed,
    # and the correct python version is used
    source "${virtual_env}/bin/activate"

    VENV_LIB="${virtual_env}/lib/python3.6/site-packages"

    NDK="/opt/rh/rh-python36/root/usr/lib/python3.6/site-packages/sdk_protos"
    # since 21.6
    SDK2="/usr/lib/python3.6/site-packages/sdk_protos"
    APP="/opt/demo-agents/auto-config-agent"
    export PYTHONPATH="$VENV_LIB:$NDK:$SDK2:$APP:$PYTHONPATH"

    export http_proxy=""
    export https_proxy=""
    export no_proxy=""
    python3 /opt/demo-agents/auto-config-agent/auto-config-agent.py &

    child=$!
    wait "$child"

}

main "$@"
