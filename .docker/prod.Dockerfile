ARG VERSION=unstable

FROM greenbone/openvas-scanner:${VERSION}

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

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

COPY dist/* /ospd-openvas

RUN python3 -m pip install /ospd-openvas/*

RUN apt-get purge -y gcc python3-dev && apt-get autoremove -y

ENTRYPOINT ["/usr/local/bin/entrypoint"]

CMD ["ospd-openvas", "--disable-notus-hashsum-verification", "--config", "/etc/gvm/ospd-openvas.conf", "-f", "-m", "666"]
