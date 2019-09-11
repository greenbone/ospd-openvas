# -*- coding: utf-8 -*-
# Copyright (C) 2018-2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

""" Access management for redis-based OpenVAS Scanner Database."""
import logging
import subprocess
import sys
import time

import redis

from ospd.errors import RequiredArgument
from ospd_openvas.errors import OspdOpenvasError

SOCKET_TIMEOUT = 60  # in seconds
LIST_FIRST_POS = 0
LIST_LAST_POS = -1
LIST_ALL = 0

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
    "NVT_NAME_POS",
]

logger = logging.getLogger(__name__)


class OpenvasDB(object):
    """ Class to connect to redis, to perform queries, and to move
    from a KB to another."""

    # Name of the namespace usage bitmap in redis.
    DBINDEX_NAME = "GVM.__GlobalDBIndex"

    def __init__(self):
        # Path to the Redis socket.
        self.db_address = None

        self.max_dbindex = 0
        self.db_index = 0
        self.rediscontext = None

    @staticmethod
    def _parse_openvas_db_address(result):
        """ Return the path to the redis socket.
        Arguments:
            result (bytes) Output of `openvas -s`
        Return redis unix socket path.
        """
        path = None
        result = result.decode('ascii')
        for conf in result.split('\n'):
            if conf.find('db_address') == 0:
                path = conf.split('=')
                break

        if not path:
            raise OspdOpenvasError(
                'Redis Error: Not possible to '
                'find the path to the redis socket.'
            )
        return path[1].strip()

    def get_db_connection(self):
        """ Retrieve the db address from openvas config.
        """
        if self.db_address:
            return
        try:
            result = subprocess.check_output(
                ['openvas', '-s'], stderr=subprocess.STDOUT
            )
        except (PermissionError, OSError) as e:
            sys.exit(
                "ERROR: %s: Not possible to run openvas. %s"
                % (self.get_db_connection.__name__, e)
            )

        if result:
            path = self._parse_openvas_db_address(result)

        self.db_address = path

    def max_db_index(self):
        """Set the number of databases have been configured into kbr struct.
        """
        ctx = self.kb_connect()
        resp = ctx.config_get('databases')

        if len(resp) == 1:
            self.max_dbindex = int(resp.get('databases'))
        else:
            raise OspdOpenvasError(
                'Redis Error: Not possible ' 'to get max_dbindex.'
            )

    def set_redisctx(self, ctx):
        """ Set the current rediscontext.
        Arguments:
            ctx (object): Redis context to be set as default.
        """
        if not ctx:
            raise RequiredArgument('set_redisctx', 'ctx')
        self.rediscontext = ctx

    def db_init(self):
        """ Set db_address and max_db_index. """
        self.get_db_connection()
        self.max_db_index()

    def try_database_index(self, ctx, kb):
        """ Check if a redis kb is already in use. If not, set it
        as in use and return.
        Arguments:
            ctx (object): Redis object connected to the kb with the
                DBINDEX_NAME key.
            kb (int): Kb number intended to be used.

        Return True if it is possible to use the kb. False if the given kb
            number is already in use.
        """
        _in_use = 1
        try:
            resp = ctx.hsetnx(self.DBINDEX_NAME, kb, _in_use)
        except:
            raise OspdOpenvasError(
                'Redis Error: Not possible to set %s.' % self.DBINDEX_NAME
            )

        if resp == 1:
            return True
        return False

    def kb_connect(self, dbnum=0):
        """ Connect to redis to the given database or to the default db 0 .

        Arguments:
            dbnum (int, optional): The db number to connect to.

        Return a redis context on success.
        """
        self.get_db_connection()
        tries = 5
        while tries:
            try:
                ctx = redis.Redis(
                    unix_socket_path=self.db_address,
                    db=dbnum,
                    socket_timeout=SOCKET_TIMEOUT,
                    encoding="latin-1",
                    decode_responses=True,
                )
                ctx.keys("test")
            except (redis.exceptions.ConnectionError, FileNotFoundError) as err:
                logger.debug(
                    'Redis connection lost: %s. Trying again in 5 seconds.', err
                )
                tries = tries - 1
                time.sleep(5)
                continue
            break

        if not tries:
            raise OspdOpenvasError(
                'Redis Error: Not possible to connect to the kb.'
            )

        self.db_index = dbnum
        return ctx

    def db_find(self, patt):
        """ Search a pattern inside all kbs. When find it return it.
        """
        for i in range(0, self.max_dbindex):
            ctx = self.kb_connect(i)
            if ctx.keys(patt):
                return ctx

        return None

    def kb_new(self):
        """ Return a new kb context to an empty kb.
        """
        ctx = self.db_find(self.DBINDEX_NAME)
        for index in range(1, self.max_dbindex):
            if self.try_database_index(ctx, index):
                ctx = self.kb_connect(index)
                ctx.flushdb()
                return ctx

        return None

    def get_kb_context(self):
        """ Get redis context if it is already connected or do a connection.
        """
        if self.rediscontext is not None:
            return self.rediscontext

        self.rediscontext = self.db_find(self.DBINDEX_NAME)

        if self.rediscontext is None:
            raise OspdOpenvasError(
                'Redis Error: Problem retrieving Redis Context'
            )

        return self.rediscontext

    def select_kb(self, ctx, kbindex, set_global=False):
        """ Use an existent redis connection and select a redis kb.
        If needed, set the ctx as global.
        Arguments:
            ctx (redis obj): Redis context to use.
            kbindex (str): The new kb to select
            set_global (bool, optional): If should be the global context.
        """
        if not ctx:
            raise RequiredArgument('select_kb', 'ctx')
        if not kbindex:
            raise RequiredArgument('select_kb', 'kbindex')

        ctx.execute_command('SELECT ' + str(kbindex))
        if set_global:
            self.set_redisctx(ctx)
            self.db_index = str(kbindex)

    def get_list_item(
        self, name, ctx=None, start=LIST_FIRST_POS, end=LIST_LAST_POS
    ):
        """ Returns the specified elements from `start` to `end` of the
        list stored as `name`.

        Arguments:
            name (str): key name of a list.
            ctx (redis obj, optional): Redis context to use.
            start (int, optional): first range element to get.
            end (int, optional): last range element to get.

        Return List specified elements in the key.
        """
        if not name:
            raise RequiredArgument('get_list_item', 'name')

        if not ctx:
            ctx = self.get_kb_context()
        return ctx.lrange(name, start, end)

    def remove_list_item(self, key, value, ctx=None):
        """ Remove item from the key list.
        Arguments:
            key (str): key name of a list.
            value (str): Value to be removed from the key.
            ctx (redis obj, optional): Redis context to use.
        """
        if not key:
            raise RequiredArgument('remove_list_item', 'key')
        if not value:
            raise RequiredArgument('remove_list_item ', 'value')

        if not ctx:
            ctx = self.get_kb_context()
        ctx.lrem(key, count=LIST_ALL, value=value)

    def get_single_item(self, name, ctx=None, index=LIST_FIRST_POS):
        """ Get a single KB element.
        Arguments:
            name (str): key name of a list.
            ctx (redis obj, optional): Redis context to use.
            index (int, optional): index of the element to be return.
        Return an element.
        """
        if not name:
            raise RequiredArgument('get_single_item', 'name')

        if not ctx:
            ctx = self.get_kb_context()
        return ctx.lindex(name, index)

    def add_single_item(self, name, values, ctx=None):
        """ Add a single KB element with one or more values.
        Arguments:
            name (str): key name of a list.
            value (list): Elements to add to the key.
            ctx (redis obj, optional): Redis context to use.
        """
        if not name:
            raise RequiredArgument('add_list_item', 'name')
        if not values:
            raise RequiredArgument('add_list_item', 'value')

        if not ctx:
            ctx = self.get_kb_context()
        ctx.rpush(name, *set(values))

    def set_single_item(self, name, value, ctx=None):
        """ Set (replace) a single KB element.
        Arguments:
            name (str): key name of a list.
            value (list): New elements to add to the key.
            ctx (redis obj, optional): Redis context to use.
        """
        if not name:
            raise RequiredArgument('set_single_item', 'name')
        if not value:
            raise RequiredArgument('set_single_item', 'value')

        if not ctx:
            ctx = self.get_kb_context()
        pipe = ctx.pipeline()
        pipe.delete(name)
        pipe.rpush(name, *set(value))
        pipe.execute()

    def get_pattern(self, pattern, ctx=None):
        """ Get all items stored under a given pattern.
        Arguments:
            pattern (str): key pattern to match.
            ctx (redis obj, optional): Redis context to use.
        Return a list with the elements under the matched key.
        """
        if not pattern:
            raise RequiredArgument('get_pattern', 'pattern')

        if not ctx:
            ctx = self.get_kb_context()
        items = ctx.keys(pattern)

        elem_list = []
        for item in items:
            elem_list.append(
                [
                    item,
                    ctx.lrange(item, start=LIST_FIRST_POS, end=LIST_LAST_POS),
                ]
            )
        return elem_list

    def get_elem_pattern_by_index(self, pattern, index=1, ctx=None):
        """ Get all items with index 'index', stored under
        a given pattern.
        Arguments:
            pattern (str): key pattern to match.
            index (int, optional): Index of the element to get from the list.
            ctx (redis obj, optional): Redis context to use.
        Return a list with the elements under the matched key and given index.
        """
        if not pattern:
            raise RequiredArgument('get_elem_pattern_by_index', 'pattern')

        if not ctx:
            ctx = self.get_kb_context()
        items = ctx.keys(pattern)

        elem_list = []
        for item in items:
            elem_list.append([item, ctx.lindex(item, index)])
        return elem_list

    def release_db(self, kbindex=0):
        """ Connect to redis and select the db by index.
        Flush db and delete the index from dbindex_name list.
        Arguments:
            kbindex (int, optional): KB index to flush and release.
        """
        ctx = self.kb_connect(kbindex)
        ctx.flushdb()
        ctx = self.kb_connect()
        ctx.hdel(self.DBINDEX_NAME, kbindex)

    def get_result(self, ctx=None):
        """ Get and remove the oldest result from the list.
        Arguments:
            ctx (redis obj, optional): Redis context to use.
        Return a list with scan results
        """
        if not ctx:
            ctx = self.get_kb_context()
        return ctx.rpop("internal/results")

    def get_status(self, ctx=None):
        """ Get and remove the oldest host scan status from the list.
        Arguments:
            ctx (redis obj, optional): Redis context to use.
        Return a string which represents the host scan status.
        """
        if not ctx:
            ctx = self.get_kb_context()
        return ctx.rpop("internal/status")

    def get_host_scan_scan_start_time(self, ctx=None):
        """ Get the timestamp of the scan start from redis.
        Arguments:
            ctx (redis obj, optional): Redis context to use.
        Return a string with the timestamp of the scan start.
        """
        if not ctx:
            ctx = self.get_kb_context()
        return ctx.rpop("internal/start_time")

    def get_host_scan_scan_end_time(self, ctx=None):
        """ Get the timestamp of the scan end from redis.
        Arguments:
            ctx (redis obj, optional): Redis context to use.
        Return a string with the timestamp of scan end .
        """
        if not ctx:
            ctx = self.get_kb_context()
        return ctx.rpop("internal/end_time")

    def get_host_ip(self, ctx=None):
        """ Get the ip of host_kb.
        Arguments:
            ctx (redis obj, optional): Redis context to use.
        Return a string with the ip of the host being scanned.
        """
        if not ctx:
            ctx = self.get_kb_context()
        return self.get_single_item("internal/ip")
