#!/usr/bin/env bash
# Is a convenience script to start redis, ospd-openvas and execute `go test`
set -e

shutdown() {
  kill -9 $(cat /var/run/ospd/ospd.pid)
  redis-cli -s /var/run/redis/redis.sock SHUTDOWN
}

trap shutdown EXIT

sudo redis-server /etc/redis/redis.conf
ospd-openvas -u /var/run/ospd/ospd.sock -l /var/log/gvm/ospd.log
cd /usr/local/src/ospd-openvas/smoketest
go test ./...
