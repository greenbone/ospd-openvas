ARG VERSION=stable

FROM greenbone/openvas-scanner:${VERSION}

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /
COPY ./config/ospd-openvas.conf /etc/gvm/ospd.conf
WORKDIR /ospd-openvas

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
    python3 \
    python3-pip \
    python3-rpm && \
    apt-get remove --purge --auto-remove -y && \
    rm -rf /var/lib/apt/lists/*

RUN addgroup --gid 1001 --system ospd-openvas && \
    adduser --no-create-home --shell /bin/false --disabled-password --uid 1001 --system --group ospd-openvas

COPY dist/* /ospd-openvas

RUN python3 -m pip install /ospd-openvas/*

ENTRYPOINT ["ospd-openvas"]
CMD ["-c", "/etc/gvm/ospd.conf", "-f", "-m", "666"]
