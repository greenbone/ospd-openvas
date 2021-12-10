ARG VERSION=stable

FROM greenbone/openvas-scanner:${VERSION}

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

<<<<<<< HEAD
WORKDIR /
COPY ./config/ospd-openvas.conf /etc/gvm/ospd.conf
=======
COPY ./config/ospd-openvas.conf /etc/gvm/ospd-openvas.conf
<<<<<<< HEAD
>>>>>>> f31f015d (Remove unnecessary WORKDIR command)
=======
COPY .docker/entrypoint.sh /usr/local/bin/entrypoint

>>>>>>> dc4ddb03 (Use gosu to run ospd-openvas with a dedicated user)
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

<<<<<<< HEAD
=======
RUN chgrp -R ospd-openvas /etc/openvas/ && \
    chown ospd-openvas /var/log/gvm && \
    chmod 755 /etc/openvas /var/log/gvm && \
    chmod 644 /etc/openvas/openvas_log.conf && \
    chmod 755 /usr/local/bin/entrypoint

>>>>>>> dc4ddb03 (Use gosu to run ospd-openvas with a dedicated user)
COPY dist/* /ospd-openvas

RUN python3 -m pip install /ospd-openvas/*

<<<<<<< HEAD
# Create empty config file and change owner for /etc/openvas/openvas_log.conf
# because the openvas process executed by ospd requires sudo on this file
RUN touch /etc/openvas/openvas_log.conf && \
    chown ospd-openvas:sudo /etc/openvas/openvas_log.conf

USER ospd-openvas

ENTRYPOINT ["ospd-openvas"]
CMD ["-c", "/etc/gvm/ospd.conf", "-f", "-m", "666"]
=======
ENTRYPOINT ["/usr/local/bin/entrypoint"]

CMD ["ospd-openvas", "--config", "/etc/gvm/ospd-openvas.conf", "-f", "-m", "666"]
>>>>>>> dc4ddb03 (Use gosu to run ospd-openvas with a dedicated user)
