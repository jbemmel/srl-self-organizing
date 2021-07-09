ARG SR_LINUX_RELEASE
FROM registry.srlinux.dev/pub/srlinux:$SR_LINUX_RELEASE

RUN sudo curl -sL https://github.com/karimra/gnmic/releases/download/v0.16.0/gnmic_0.16.0_Linux_x86_64.rpm -o /tmp/gnmic.rpm && sudo yum localinstall -y /tmp/gnmic.rpm

RUN printf '%s\n' \
  '#!/bin/bash' \
  '' \
  'mkdir -p /etc/opt/srlinux/appmgr && cp /home/appmgr/* /etc/opt/srlinux/appmgr/' \
  'exit $?' \
  \
> /tmp/42.sh && sudo mv /tmp/42.sh /opt/srlinux/bin/bootscript/42_sr_copy_custom_appmgr.sh && \
  sudo chmod a+x /opt/srlinux/bin/bootscript/42_sr_copy_custom_appmgr.sh

# Install pyGNMI to /usr/local/lib[64]/python3.6/site-packages
RUN sudo yum-config-manager --disable ipdcentos ipdrepo ius && sudo yum clean all
RUN sudo yum install -y python3-pip gcc-c++ && \
    sudo python3 -m pip install pip --upgrade && \
    sudo python3 -m pip install pygnmi

# RUN sudo mkdir -p /etc/opt/srlinux/appmgr/ && sudo cp /home/appmgr/* /etc/opt/srlinux/appmgr/

# Install balena, a modern Docker application to run containers within SRL
# Requires cSRL to be started using
# sudo docker run -it --privileged -v /tmp/var_lib_docker:/var/lib/balena-engine srl/auto-config:latest
# RUN curl -sfL https://balena.io/engine/install.sh | sh

# Add Paris traceroute
# COPY --from=paris-traceroute /usr/local/bin/paris-* /usr/local/bin/
# COPY --from=paris-traceroute /usr/local/lib/* /usr/local/lib/

# --chown=srlinux:srlinux
# COPY ./appmgr/ /etc/opt/srlinux/appmgr/ # doesn't stick
COPY ./appmgr/ /home/appmgr

# Add FIB agent
# COPY ./srl-demo-agent/demo_* /home/appmgr/

# Add CLI enhancements
COPY ./mgmt_cli_engine_command_loop.py /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/srlinux/mgmt/cli_engine/command_loop.py

# Apply IPv6 column width fixes
RUN sudo sed -i 's/(ancestor_keys=False, print_on_data=True)/(ancestor_keys=False,print_on_data=True,widths=[28])/g' \
    /opt/srlinux/python/virtual-env/lib/python3.6/site-packages/srlinux/mgmt/cli/plugins/reports/bgp_evpn*_routes_report.py

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_AUTO_CONFIG_RELEASE="[custom build]"
ENV SRL_AUTO_CONFIG_RELEASE=$SRL_AUTO_CONFIG_RELEASE
