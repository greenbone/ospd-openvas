ARG VERSION=oldstable

FROM greenbone/openvas-scanner:${VERSION}

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY ./config/ospd-openvas.conf /etc/gvm/ospd-openvas.conf
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

WORKDIR /ospd-openvas

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    gosu \
    python3 \
    python3-pip && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --gid 1001 --system ospd-openvas && \
    adduser --no-create-home --shell /bin/false --disabled-password \
    --uid 1001 --system --group ospd-openvas

RUN chgrp -R ospd-openvas /etc/openvas/ && \
    chown ospd-openvas /var/log/gvm && \
    chmod 755 /etc/openvas /var/log/gvm && \
    chmod 644 /etc/openvas/openvas_log.conf && \
    chmod 755 /usr/local/bin/entrypoint

COPY dist/* /ospd-openvas

RUN python3 -m pip install /ospd-openvas/*

ENTRYPOINT ["/usr/local/bin/entrypoint"]

CMD ["ospd-openvas", "--config", "/etc/gvm/ospd-openvas.conf", "-f", "-m", "666"]
