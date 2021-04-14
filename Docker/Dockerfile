FROM registry.srlinux.dev/pub/srlinux:latest

RUN curl -sL https://github.com/karimra/gnmic/releases/download/v0.10.0/gnmic_0.10.0_Linux_x86_64.rpm -o /tmp/gnmic.rpm && yum localinstall -y /tmp/gnmic.rpm

COPY --chown=srlinux:srlinux . /etc/opt/srlinux/appmgr/
