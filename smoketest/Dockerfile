
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
    curl &&\
	apt-get remove --purge --auto-remove -y &&\
	rm -rf /var/lib/apt/lists/*
# due to old version in buster
RUN curl -L https://golang.org/dl/go1.17.2.linux-amd64.tar.gz -o /tmp/go.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf /tmp/go.tar.gz &&\
    rm /tmp/go.tar.gz


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
RUN echo "persistence true" >> /etc/mosquitto.conf
RUN echo "mqtt_server_uri = localhost:1883" >> /etc/openvas/openvas.conf
RUN chown mosquitto:mosquitto /run/mosquitto
RUN mkdir -p /var/log/mosquitto/
RUN chown mosquitto:mosquitto /var/log/mosquitto
RUN chmod 774 /var/log/mosquitto

WORKDIR /usr/local/src/ospd-openvas/smoketest
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o /usr/local/bin/ospd-openvas-smoketests cmd/test/main.go
RUN mv /usr/local/src/ospd-openvas/smoketest/run-tests.sh /usr/local/bin/run

RUN rm -rf /usr/local/go
RUN rm -rf /usr/local/src/ospd-openvas
RUN apt-get remove --purge --auto-remove -y curl python3-pip python3-packaging

USER gvm
CMD /usr/local/bin/run
