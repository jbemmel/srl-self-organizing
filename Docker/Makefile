NAME        := srl/auto-config
LAST_COMMIT := $(shell sh -c "git log -1 --pretty=%h")
TODAY       := $(shell sh -c "date +%Y%m%d_%H%M")
TAG         := ${TODAY}.${LAST_COMMIT}
IMG         := ${NAME}:${TAG}
LATEST      := ${NAME}:latest
# HTTP_PROXY  := "http://proxy.lbs.alcatel-lucent.com:8000"

build:
	cd .. && sudo docker build --build-arg SRL_AUTO_CONFIG_RELEASE=${TAG} --build-arg http_proxy=${HTTP_PROXY} --build-arg https_proxy=${HTTP_PROXY} \
	         -f Docker/Dockerfile -t ${IMG} .
	sudo docker tag ${IMG} ${LATEST}

build-frr:
	cd .. && sudo docker build --build-arg SRL_AUTO_CONFIG_RELEASE=${TAG} --build-arg http_proxy=${HTTP_PROXY} --build-arg https_proxy=${HTTP_PROXY} \
	         -f Docker/Dockerfile.frr -t frr-with-lldp .
	sudo docker tag frr-with-lldp frr-with-lldp:latest

login:
	docker log -u ${DOCKER_USER} -p ${DOCKER_PASS}
