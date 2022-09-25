#!/bin/bash

# Set openvas and nmap caps, with some compose installations docker forgets it.
setcap cap_net_raw,cap_net_admin+eip /usr/local/sbin/openvas
setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

exec gosu ospd-openvas "$@"
