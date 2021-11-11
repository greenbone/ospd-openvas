
FROM greenbone/openvas-scanner:unstable

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y \
    redis \
    git \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-packaging \
    python3-wrapt \
    python3-cffi \
    python3-psutil \
    python3-lxml \
    python3-defusedxml \
    python3-paramiko \
    python3-redis \
    curl \
    sudo &&\
	apt-get remove --purge --auto-remove -y &&\
	rm -rf /var/lib/apt/lists/*

# due to old version in buster
RUN curl -L https://golang.org/dl/go1.17.2.linux-amd64.tar.gz -o /tmp/go.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf /tmp/go.tar.gz &&\
    rm /tmp/go.tar.gz
RUN useradd -rm -d /home/gvm -s /bin/bash -g root -g redis -G sudo -u 1000 gvm
RUN  echo 'gvm:test' | chpasswd
RUN echo "gvm ALL = NOPASSWD: /usr/sbin/openvas" > /etc/sudoers.d/allow_openvas
RUN echo "gvm ALL = NOPASSWD: /usr/bin/redis-server" > /etc/sudoers.d/allow_redis-server
COPY redis.conf /etc/redis/redis.conf
COPY --chmod=7777 . /usr/local/src/it
RUN mv /usr/local/src/it/data/plugins/* /var/lib/openvas/plugins
RUN mkdir /run/redis
RUN chown redis:redis /run/redis
RUN mkdir -p /home/gvm/
RUN mkdir -p /var/run/ospd/
RUN chown gvm:sudo /var/run/ospd
RUN touch /etc/openvas/openvas_log.conf
# hack since ospd-openvas does execute `openvas --updatye-vt-info` without sudo 
RUN chown gvm:sudo /etc/openvas/openvas_log.conf
WORKDIR /usr/local/src
RUN git clone --single-branch --depth=1 https://github.com/greenbone/ospd.git
RUN git clone --single-branch --depth=1 https://github.com/greenbone/ospd-openvas.git
WORKDIR /usr/local/src/ospd
RUN python3 -m pip install .
WORKDIR /usr/local/src/ospd-openvas
RUN python3 -m pip install .
RUN chown gvm:sudo /var/log/gvm
RUN ln -s /usr/local/go/bin/* /usr/local/bin/
USER gvm
WORKDIR /usr/local/src/it
CMD /usr/local/src/it/run-tests.sh
