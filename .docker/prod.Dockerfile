ARG VERSION=oldstable

FROM debian:stable-slim as builder

COPY . /source

WORKDIR /source

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    python3 \
    python-is-python3 \
    python3-pip && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN python -m pip install --upgrade pip && \
    python3 -m pip install poetry

RUN rm -rf dist && poetry build -f wheel

FROM greenbone/openvas-scanner:${VERSION}

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
<<<<<<< HEAD

=======
ENV PIP_NO_CACHE_DIR off

COPY --from=tools /usr/local/src/bin/ospd-scans /usr/local/bin/
>>>>>>> 536c47b9 (Change: Don't use a pip cache within the container build)
COPY ./config/ospd-openvas.conf /etc/gvm/ospd-openvas.conf
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

WORKDIR /ospd-openvas

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    # gcc and python3-dev are required for psutil on arm
    gcc \
    gosu \
    python3 \
    python3-pip \
    python3-dev && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --gid 1001 --system ospd-openvas && \
    adduser --no-create-home --shell /bin/false --disabled-password \
    --uid 1001 --system --group ospd-openvas

RUN mkdir -p /run/ospd && \
    mkdir -p /var/lib/openvas && \
    chown -R ospd-openvas.ospd-openvas \
    /run/ospd /var/lib/openvas /etc/openvas /var/log/gvm && \
    chmod 755 /etc/openvas /var/log/gvm && \
    chmod 644 /etc/openvas/openvas_log.conf && \
    chmod 755 /usr/local/bin/entrypoint

COPY --from=builder /source/dist/* /ospd-openvas/

RUN python3 -m pip install /ospd-openvas/*

RUN apt-get purge -y gcc python3-dev && apt-get autoremove -y

ENTRYPOINT ["/usr/local/bin/entrypoint"]

CMD ["ospd-openvas", "--config", "/etc/gvm/ospd-openvas.conf", "-f", "-m", "666"]
