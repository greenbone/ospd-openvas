FROM ghcr.io/greenbone/data-objects:community-staging AS data_objects
RUN mv `ls -d /var/lib/gvm/data-objects/gvmd/*/*configs | sort -r | head -n 1` /policies

FROM ghcr.io/greenbone/vulnerability-tests:community-staging AS nasl
# use latest version
RUN mv `ls -d /var/lib/openvas/* | sort -r | head -n 1`/vt-data/nasl /nasl

FROM golang AS binaries
COPY --chmod=7777 smoketest /usr/local/src
WORKDIR /usr/local/src
RUN make build-cmds

FROM greenbone/openvas-scanner:unstable

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    mosquitto \
    redis \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-packaging \
    python3-wrapt \
    python3-cffi \
    python3-psutil \
    python3-lxml \
    python3-defusedxml \
    python3-redis \
    python3-gnupg \
    python3-paho-mqtt \
    openssh-server &&\
	apt-get remove --purge --auto-remove -y &&\
	rm -rf /var/lib/apt/lists/*
COPY --chmod=7777 . /usr/local/src/ospd-openvas
COPY smoketest/redis.conf /etc/redis/redis.conf
RUN rm -rf /var/lib/openvas/plugins/*
RUN cp -r /usr/local/src/ospd-openvas/smoketest/data/plugins/* /var/lib/openvas/plugins
RUN cp -r /usr/local/src/ospd-openvas/smoketest/data/notus /var/lib/openvas/plugins/notus

RUN useradd -rm -s /bin/bash -g redis -u 1000 gvm
RUN mkdir /run/redis
RUN chown gvm:redis /run/redis
RUN mkdir -p /var/run/ospd/
RUN chown gvm:redis /var/run/ospd
RUN touch /etc/openvas/openvas_log.conf
RUN chown gvm:redis /etc/openvas/openvas_log.conf
WORKDIR /usr/local/src/ospd-openvas
RUN python3 -m pip install .
RUN chown gvm:redis /var/log/gvm
RUN mkdir /run/mosquitto
RUN echo "allow_anonymous true" >> /etc/mosquitto.conf
RUN echo "pid_file /tmp/mosquitto.pid" >> /etc/mosquitto.conf
RUN echo "log_dest file /tmp/mosquitto.log" >> /etc/mosquitto.conf
RUN echo "persistence_location = /tmp/" >> /etc/mosquitto.conf
RUN echo "persistence true" >> /etc/mosquitto.conf
RUN echo "mqtt_server_uri = localhost:1883" >> /etc/openvas/openvas.conf
RUN chown mosquitto:mosquitto /run/mosquitto
RUN mkdir -p /var/log/mosquitto/
RUN chown mosquitto:mosquitto /var/log/mosquitto
RUN chmod 774 /var/log/mosquitto

COPY --from=binaries /usr/local/src/bin/* /usr/local/bin/
RUN mv /usr/local/src/ospd-openvas/smoketest/run-tests.sh /usr/local/bin/run
COPY --from=nasl --chmod=7777 /nasl /usr/local/src/nasl
COPY --from=data_objects --chmod=7777 /policies /usr/local/src/policies
RUN rm -rf /usr/local/src/ospd-openvas
RUN apt-get remove --purge --auto-remove -y python3-pip python3-packaging
RUN chown -R gvm:redis /var/lib/openvas/plugins/
RUN mkdir /run/sshd
# make gvm capable of running sshd
RUN chown -R gvm:redis /etc/ssh
RUN echo 'gvm:test' | chpasswd
RUN sed -i 's/#PidFile/Pidfile/' /etc/ssh/sshd_config
USER gvm
WORKDIR /home/gvm
CMD /usr/local/bin/run
