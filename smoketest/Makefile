.PHONY: build run

MAKEFILE_PATH := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

ALTERNATIVE_HOSTS := smoketest.localdomain smoke.localdomain and.localdomain mirrors.localdomain

ADD_HOST := $(addprefix --add-host ,$(addsuffix :127.0.0.1, ${ALTERNATIVE_HOSTS}))

RUN_PARAM := run --rm --privileged ${ADD_HOST}
VARIANT := community
DATA_OBJECTS := ghcr.io/greenbone/data-objects:${VARIANT}-staging
NASL := ghcr.io/greenbone/vulnerability-tests:${VARIANT}-staging

ifndef GO
	GO := go
endif
GO_BUILD := CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ${GO} build -o

ifndef SORT
	SORT := sort -r
endif

ifndef NASL_ROOT
	NASL_ROOT := `ls -d /var/lib/openvas/* | ${SORT} | head -n 1`
endif
ifndef POLICY_ROOT
	POLICY_ROOT := `find /var/lib/gvm/data-objects/gvmd/*/*configs -type d | ${SORT} | head -n 1`
endif

all: build run

build-cmds:
	- mkdir bin || true
	 ${GO_BUILD} bin/ospd-openvas-smoketests cmd/test/main.go
	 ${GO_BUILD} bin/ospd-policy-feed cmd/feed-preparer/main.go
	 ${GO_BUILD} bin/ospd-scans cmd/scans/main.go

build:
	cd .. && DOCKER_BUILDKIT=1 docker build -t greenbone/ospd-openvas-smoketests -f smoketest/Dockerfile . 2>build.log && rm build.log || (cat build.log && false)

run:
	docker ${RUN_PARAM} greenbone/ospd-openvas-smoketests

interactive:
	docker ${RUN_PARAM} --name ospd-st-ia -it greenbone/ospd-openvas-smoketests bash

update-nasl-image:
	- docker pull ${NASL} || ( printf "are you logged in ghr.io within docker and an access token `read:packages`?\n" && false )

fetch-nasl: update-nasl-image
	- docker run -it -v ${MAKEFILE_PATH}:/mnt --rm ${NASL} sh -c 'cp -rv ${NASL_ROOT}/vt-data/nasl /mnt/.nasl && chmod -R 777 /mnt/.nasl'

update-data-objects-image:
	- docker pull ${DATA_OBJECTS} || ( printf "are you logged in ghr.io within docker and an access token `read:packages`?\n" && false )

fetch-scan-configs: update-data-objects-image
	- docker run -it -v ${MAKEFILE_PATH}:/mnt --rm ${DATA_OBJECTS} sh -c 'install -D -v -m 777 ${POLICY_ROOT}/* -t /mnt/.scan-config'
