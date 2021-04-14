FROM registry.srlinux.dev/pub/srlinux:latest

RUN sudo curl -sL https://github.com/karimra/gnmic/releases/download/v0.10.0/gnmic_0.10.0_Linux_x86_64.rpm -o /tmp/gnmic.rpm && sudo yum localinstall -y /tmp/gnmic.rpm

COPY --chown=srlinux:srlinux . /etc/opt/srlinux/appmgr/

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_AUTOCONFIG_RELEASE="[custom build]"
ENV SRL_AUTOCONFIG_RELEASE=$SRL_AUTOCONFIG_RELEASE
