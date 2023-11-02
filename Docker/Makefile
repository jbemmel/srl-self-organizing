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

rpm:
	docker run --rm -v ${PWD}/..:/tmp -w /tmp goreleaser/nfpm package \
    --config /tmp/fpmConfig.yml \
    --target /tmp \
    --packager rpm
