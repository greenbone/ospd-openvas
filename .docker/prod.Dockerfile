ARG VERSION=stable

FROM greenbone/openvas-scanner:${VERSION}

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

<<<<<<< HEAD
WORKDIR /
COPY ./config/ospd-openvas.conf /etc/gvm/ospd.conf
=======
COPY ./config/ospd-openvas.conf /etc/gvm/ospd-openvas.conf
>>>>>>> f31f015d (Remove unnecessary WORKDIR command)
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

COPY dist/* /ospd-openvas

RUN python3 -m pip install /ospd-openvas/*

# Create empty config file and change owner for /etc/openvas/openvas_log.conf
# because the openvas process executed by ospd requires sudo on this file
RUN touch /etc/openvas/openvas_log.conf && \
    chown ospd-openvas:sudo /etc/openvas/openvas_log.conf

USER ospd-openvas

ENTRYPOINT ["ospd-openvas"]
CMD ["-c", "/etc/gvm/ospd.conf", "-f", "-m", "666"]
