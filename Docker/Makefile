NAME        := srl/auto-config-v2
LAST_COMMIT := $(shell sh -c "git log -1 --pretty=%h")
TODAY       := $(shell sh -c "date +%Y%m%d_%H%M")
TAG         := ${TODAY}.${LAST_COMMIT}
IMG         := ${NAME}:${TAG}
LATEST      := ${NAME}:latest
# HTTP_PROXY  := "http://proxy.lbs.alcatel-lucent.com:8000"

ifndef SR_LINUX_RELEASE
override SR_LINUX_RELEASE="latest"
endif

.PHONY: build all rpm

build:
	cd .. && sudo docker build --build-arg SRL_AUTO_CONFIG_RELEASE=${TAG} --build-arg http_proxy=${HTTP_PROXY} --build-arg https_proxy=${HTTP_PROXY} \
	                           --build-arg SR_LINUX_RELEASE="${SR_LINUX_RELEASE}" \
	         -f Docker/Dockerfile -t ${IMG} .
	sudo docker tag ${IMG} ${LATEST}

build-submodules:
	make -C ../srl-baseimage

all: build-submodules build build-frr build-alpine

build-frr:
	cd .. && sudo docker build --build-arg http_proxy=${HTTP_PROXY} --build-arg https_proxy=${HTTP_PROXY} \
	         -f Docker/Dockerfile.frr -t frr-with-lldp .
	sudo docker tag frr-with-lldp frr-with-lldp:latest

build-alpine:
		cd .. && sudo docker build --build-arg http_proxy=${HTTP_PROXY} --build-arg https_proxy=${HTTP_PROXY} \
		         -f Docker/Dockerfile.alpine -t alpine-with-lldp .
		sudo docker tag alpine-with-lldp alpine-with-lldp:latest

lint-yang:
	cd .. && sudo docker run --rm -v $$(pwd)/src/auto-config-agent/models:/work ghcr.io/hellt/yanglint auto-config-agent.yang

CREATE_CONTAINER := $(shell docker create ${LATEST})
SET_CONTAINER_ID = $(eval CONTAINER_ID=$(CREATE_CONTAINER))
rpm: build
	mkdir -p rpmbuild
	$(SET_CONTAINER_ID)
	docker cp --follow-link ${CONTAINER_ID}:/opt/demo-agents/ rpmbuild/
	docker rm ${CONTAINER_ID}
	find rpmbuild/ -type l -delete # Purge (broken) symlinks
	find rpmbuild/ -name test* | xargs rm -rf # Remove test code
	docker run --rm -v ${PWD}/..:/tmp -w /tmp goreleaser/nfpm package \
    --config /tmp/Docker/fpmConfig.yml \
    --target /tmp \
    --packager rpm
	# rm -rf rpmbuild

fpm:
	cd .. && fpm \
    -s dir -t rpm \
    -p auto-config-agent-1.0.1-1.x86_64.rpm \
    --name auto-config-agent \
    --license apache20 \
    --version 1.0.1 \
    --architecture all \
    --description "Auto-config agent for SR Linux" \
    --url "https://github.com/jbemmel/srl-self-organizing" \
    --maintainer "Jeroen van Bemmel <jeroen.van_bemmel at nokia dot com>" \
    auto-config-agent.yml=/etc/opt/srlinux/appmgr/auto-config-agent.yml \
	src/=/opt/demo-agents/