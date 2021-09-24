ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE
# FROM ghcr.io/nokia/srlinux:$SR_LINUX_RELEASE
# FROM registry.srlinux.dev/pub/srlinux:$SR_LINUX_RELEASE

# Install balena, a modern Docker application to run containers within SRL
# Requires cSRL to be started using
# sudo docker run -it --privileged -v /tmp/var_lib_docker:/var/lib/balena-engine srl/auto-config:latest
# RUN curl -sfL https://balena.io/engine/install.sh | sh

# Install FRR stable, enable BGP daemon
#RUN curl https://rpm.frrouting.org/repo/frr-stable-repo-1-0.el8.noarch.rpm -o /tmp/repo.rpm && \
#    sudo yum install -y /tmp/repo.rpm && \
#    sudo yum install -y frr frr-pythontools && \
#    sudo sed -i 's/bgpd=no/bgpd=yes/g' /etc/frr/daemons && \
#    rm -f /tmp/repo.rpm

# Add Paris traceroute
# COPY --from=paris-traceroute /usr/local/bin/paris-* /usr/local/bin/
# COPY --from=paris-traceroute /usr/local/lib/* /usr/local/lib/

RUN sudo mkdir -p /etc/opt/srlinux/appmgr/ /opt/demo-agents/
COPY --chown=srlinux:srlinux ./auto-config-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/demo-agents/

# Add FIB agent
# COPY ./srl-demo-agent/demo_* /home/appmgr/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH pylint --load-plugins=pylint_protobuf -E /opt/demo-agents/auto-config-agent

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_AUTO_CONFIG_RELEASE="[custom build]"
ENV SRL_AUTO_CONFIG_RELEASE=$SRL_AUTO_CONFIG_RELEASE
