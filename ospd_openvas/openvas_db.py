# -*- coding: utf-8 -*-
# Description:
# Access management for redis-based OpenVAS Scanner Database
#
# Authors:
# Juan José Nicola <juan.nicola@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

""" Functions to retrieve and store data from redis-based
    OpenVAS Scanner database. """

import redis
import subprocess

SOCKET_TIMEOUT = 60  # in seconds

# Possible positions of nvt values in cache list.
NVT_META_FIELDS = [
    "NVT_FILENAME_POS",
    "NVT_REQUIRED_KEYS_POS",
    "NVT_MANDATORY_KEYS_POS",
    "NVT_EXCLUDED_KEYS_POS",
    "NVT_REQUIRED_UDP_PORTS_POS",
    "NVT_REQUIRED_PORTS_POS",
    "NVT_DEPENDENCIES_POS",
    "NVT_TAGS_POS",
    "NVT_CVES_POS",
    "NVT_BIDS_POS",
    "NVT_XREFS_POS",
    "NVT_CATEGORY_POS",
    "NVT_TIMEOUT_POS",
    "NVT_FAMILY_POS",
    "NVT_NAME_POS",]


class OpenvasDB(object):
    """ Class to connect to redis, to perform queries, and to move
    from a KB to another."""

    def __init__(self):
        # Path to the Redis socket.
        self.db_address = ""

        # Name of the namespace usage bitmap in redis.
        self.dbindex_name = "GVM.__GlobalDBIndex"
        self.max_dbindex = 0
        self.db_index = 0
        self.rediscontext = None

    def get_db_connection(self):
        """ Retrieve the db address from openvassd config.
        """
        try:
            result = subprocess.check_output(['openvassd', '-s'],
                                             stderr=subprocess.STDOUT)
            result = result.decode('ascii')
        except OSError:
            # the command is not available
            return 2

        if result is None:
            return 2

        path = None
        for conf in result.split('\n'):
            if conf.find("db_address") == 0:
                path = conf.split('=')
                break

        if path is None:
            return 2

        self.db_address = str.strip(path[1])


    def max_db_index(self):
        """Set the number of databases have been configured into kbr struct.
        """
        try:
            ctx = self.kb_connect()
            resp = ctx.config_get("databases")
        except redis.RedisError:
            return 2

        if isinstance(resp, dict) is False:
            return 2
        if len(resp) == 1:
            self.max_dbindex = int(resp["databases"])
        else:
            print("Redis: unexpected reply length %d" % len(resp))
            return 2

    def set_redisctx(self, ctx):
        """ Set the current rediscontext.
        """
        self.rediscontext = ctx

    def db_init(self):
        """ Set db_address and max_db_index. """
        if self.get_db_connection() or self.max_db_index():
            return False
        return True

    def try_database_index(self, ctx, i):
        """ Check if it is already in use. If not set it as in use and return.
        """
        try:
            resp = ctx.hsetnx(self.dbindex_name, i, 1)
        except:
            return 2

        if isinstance(resp, int) is False:
            return 2

        if resp == 1:
            return 1

    def kb_connect(self, dbnum=0):
        """ Connect to redis to the given database or to the default db 0 .
        """
        if self.get_db_connection() is 2:
            return 2
        try:
            ctx = redis.Redis(unix_socket_path=self.db_address,
                              db=dbnum,
                              socket_timeout=SOCKET_TIMEOUT, charset="latin-1",
                              decode_responses=True)
        except ConnectionError as e:
            return {"error": str(e)}
        self.db_index = dbnum
        return ctx

    def db_find(self, patt):
        """ Search a pattern inside all kbs. When find it return it.
        """
        for i in range(0, self.max_dbindex):
            ctx = self.kb_connect (i)
            if ctx.keys(patt):
                return ctx

    def kb_new(self):
        """ Return a new kb context to an empty kb.
        """
        ctx = self.db_find(self.dbindex_name)
        for index in range(1, self.max_dbindex):
                if self.try_database_index(ctx, index) == 1:
                    ctx = self.kb_connect(index)
                    return ctx

    def get_kb_context(self):
        """ Get redis context if it is already connected or do a connection.
        """
        if self.rediscontext is not None:
            return self.rediscontext

        self.rediscontext = self.db_find(self.dbindex_name)

        if self.rediscontext is None:
            print("Problem retrieving Redis Context")
            return 2

        return self.rediscontext

    def item_get_list(self, name):
        """ Get all values under a KB key list.
        The right rediscontext must be already set.
        """
        ctx = self.get_kb_context()
        return ctx.lrange(name, 0, -1)

    def remove_list_item(self, key, value):
        """ Remove item from the key list.
        The right rediscontext must be already set.
        """
        ctx = self.get_kb_context()
        ctx.lrem(key, 0, value)

    def item_get_single(self, name):
        """ Get a single KB element. The right rediscontext must be
        already set.
        """
        ctx = self.get_kb_context()
        return ctx.lindex(name, 0)

    def item_add_single(self, name, values):
        """ Add a single KB element with one or more values.
        The right rediscontext must be already set.
        """
        ctx = self.get_kb_context()
        ctx.rpush(name, *set(values))

    def item_set_single(self, name, value):
        """ Set (replace) a new single KB element. The right
        rediscontext must be already set.
        """
        ctx = self.get_kb_context()
        pipe = ctx.pipeline()
        pipe.delete(name)
        pipe.rpush(name, *set(value))
        pipe.execute()

    def item_del_single(self, name):
        """ Delete a single KB element. The right rediscontext must be
        already set.
        """
        ctx = self.get_kb_context()
        ctx.delete(name)

    def get_pattern(self, pattern):
        """ Get all items stored under a given pattern.
        """
        ctx = self.get_kb_context()
        items = ctx.keys(pattern)

        elem_list = []
        for item in items:
            elem_list.append([item, ctx.lrange(item, 0, -1)])
        return elem_list

    def get_elem_pattern_by_index(self, pattern, index=1):
        """ Get all items with index 'index', stored under
        a given pattern.
        """
        ctx = self.get_kb_context()
        items = ctx.keys(pattern)

        elem_list = []
        for item in items:
            elem_list.append([item, ctx.lindex(item, index)])
        return elem_list

    def release_db(self, kbindex=0):
        """ Connect to redis and select the db by index.
        Flush db and delete the index from dbindex_name list.
        """
        if kbindex:
            ctx = self.kb_connect(kbindex)
            ctx.flushdb()
            ctx = self.kb_connect()
            ctx.hdel(self.dbindex_name, kbindex)

    def get_result(self):
        """ Get and remove the oldest result from the list. """
        ctx = self.get_kb_context()
        return ctx.rpop("internal/results")

    def get_status(self):
        """ Get and remove the oldest host scan status from the list. """
        ctx = self.get_kb_context()
        return ctx.rpop("internal/status")

    def get_host_scan_scan_start_time(self):
        """ Get the timestamp of the scan start from redis. """
        ctx = self.get_kb_context()
        return ctx.rpop("internal/start_time")

    def get_host_scan_scan_end_time(self):
        """ Get the timestamp of the scan end from redis. """
        ctx = self.get_kb_context()
        return ctx.rpop("internal/end_time")
