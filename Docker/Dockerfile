ARG SR_LINUX_RELEASE
FROM srl/custombase:$SR_LINUX_RELEASE

RUN sudo mkdir --mode 0755 -p /etc/opt/srlinux/appmgr/ /opt/demo-agents/

# Create a Python virtual environment, note --upgrade is broken
RUN sudo python3 -m venv /opt/demo-agents/auto-config-agent/.venv --system-site-packages --without-pip
ENV VIRTUAL_ENV=/opt/demo-agents/auto-config-agent/.venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
ENV AGENT_PYTHONPATH="$VIRTUAL_ENV/lib/python3.6/site-packages:$AGENT_PYTHONPATH"
RUN $VIRTUAL_ENV/bin/python3 -m pip install --upgrade pygnmi

COPY --chown=srlinux:srlinux ./auto-config-agent.yml /etc/opt/srlinux/appmgr
COPY ./src /opt/demo-agents/

# run pylint to catch any obvious errors
RUN PYTHONPATH=$AGENT_PYTHONPATH:/opt/demo-agents/auto-config-agent \
    pylint --load-plugins=pylint_protobuf -E /opt/demo-agents/auto-config-agent

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_AUTO_CONFIG_RELEASE="[custom build]"
ENV SRL_AUTO_CONFIG_RELEASE=$SRL_AUTO_CONFIG_RELEASE
