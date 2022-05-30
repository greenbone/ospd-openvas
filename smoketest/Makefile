.PHONY: build run

ALTERNATIVE_HOSTS := smoketest.localdomain smoke.localdomain and.localdomain mirrors.localdomain

ADD_HOST := $(addprefix --add-host ,$(addsuffix :127.0.0.1, ${ALTERNATIVE_HOSTS}))

RUN_PARAM := run --rm --privileged ${ADD_HOST}

all: build run

build:
	cd .. && DOCKER_BUILDKIT=1 docker build -t greenbone/ospd-openvas-smoketests -f smoketest/Dockerfile . 2>build.log && rm build.log || (cat build.log && false)

run:
	docker ${RUN_PARAM} greenbone/ospd-openvas-smoketests

interactive:
	docker ${RUN_PARAM} -it greenbone/ospd-openvas-smoketests bash
