ARG VERSION=edge

FROM golang AS tools
COPY smoketest /usr/local/src
WORKDIR /usr/local/src
RUN make build-cmds

FROM debian:stable-slim AS builder

COPY . /source

WORKDIR /source

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    python3 \
    python-is-python3 \
    python3-pip && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --break-system-packages poetry

RUN rm -rf dist && poetry build -f wheel

FROM registry.community.greenbone.net/community/openvas-scanner:${VERSION}

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=off

COPY --from=tools /usr/local/src/bin/ospd-scans /usr/local/bin/
COPY ./config/ospd-openvas.conf /etc/gvm/ospd-openvas.conf
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

WORKDIR /ospd-openvas

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    # gcc and python3-dev are required for psutil on arm
    gcc \
    gosu \
    procps \
    python3 \
    python3-pip \
    tini \
    adduser \
    python3-dev && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

# produces the bug ` ‘/usr/share/doc/python3-impacket/examples/wmiexec.py’: [Errno 2] No such file or directory`
RUN apt-get remove -y python3-impacket || true
RUN apt-get autoremove -y

RUN addgroup --gid 1001 --system ospd-openvas && \
    adduser --no-create-home --shell /bin/false --disabled-password \
    --uid 1001 --system --group ospd-openvas

RUN mkdir -p /run/ospd && \
    mkdir -p /var/lib/openvas && \
    mkdir -p /var/lib/notus && \
    chown -R ospd-openvas.ospd-openvas \
    /run/ospd /var/lib/openvas /var/lib/notus /etc/openvas /var/log/gvm && \
    chmod 755 /etc/openvas /var/log/gvm && \
    chmod 644 /etc/openvas/openvas_log.conf && \
    chmod 755 /usr/local/bin/entrypoint

COPY --from=builder /source/dist/* /ospd-openvas/

RUN python3 -m pip install --break-system-packages /ospd-openvas/*
# install impacket via pip and not apt-get to get the latest version
RUN python3 -m pip install --break-system-packages impacket 
# openvas is expecting impacket-wmiexec to be in the path although it got renamed
# until openvas is fixed we create a symlink
RUN ln -s /usr/local/bin/wmiexec.py /usr/local/bin/impacket-wmiexec

RUN apt-get purge -y gcc python3-dev && apt-get autoremove -y

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint"]

CMD ["ospd-openvas", "--config", "/etc/gvm/ospd-openvas.conf", "-f", "-m", "666"]
