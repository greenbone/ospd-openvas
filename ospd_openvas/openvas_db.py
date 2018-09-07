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

""" Functios to retrieve and store data from redis-based OpenVAS Scanner database. """

# Needed to say that when we import ospd, we mean the package and not the
# module in that directory.
from __future__ import absolute_import
from __future__ import print_function

import redis
import subprocess

""" Path to the Redis socket. """
DB_ADDRESS = ""

""" Name of the namespace usage bitmap in redis. """
DBINDEX_NAME = "GVM.__GlobalDBIndex"
MAX_DBINDEX = 0
DB_INDEX = 0
REDISCONTEXT = None
SOCKET_TIMEOUT = 60

# Possible positions of nvt values in cache list.
nvt_meta_fields = [
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
    "NVT_COPYRIGHT_POS",
    "NVT_NAME_POS",
    "NVT_VERSION_POS",]

def get_db_connection():
    """ Retrive the db address from openvassd config.
    """
    global DB_ADDRESS
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

    DB_ADDRESS = str.strip(path[1])


def max_db_index():
    """Set the number of databases have been configured into kbr struct.
    """
    global MAX_DBINDEX
    try:
        ctx = kb_connect()
        resp = ctx.config_get("databases")
    except redis.RedisError:
        return 2

    if isinstance(resp, dict) is False:
        return 2
    if len(resp) == 1:
        MAX_DBINDEX = int(resp["databases"])
    else:
        print("Redis: unexpected reply length %d" % len(resp))
        return 2

def set_global_redisctx(ctx):
    """ Set the global set the global REDISCONTEXT.
    """
    global REDISCONTEXT
    REDISCONTEXT = ctx

def db_init():
    """ Set DB_ADDRESS and max_db_index. """
    if get_db_connection() or max_db_index():
        return False
    return True

def try_database_index(ctx, i):
    """ Check if it is already in use. If not set it as in use and return.
    """
    try:
        resp = ctx.hsetnx(DBINDEX_NAME, i, 1)
    except:
        return 2

    if isinstance(resp, int) is False:
        return 2

    if resp == 1:
        return 1

def kb_connect(dbnum=0):
    """ Connect to redis to the given database or to the default db 0 .
    """
    global DB_INDEX
    if get_db_connection() is 2:
        return 2
    try:
        ctx = redis.Redis(unix_socket_path=DB_ADDRESS,
                          db=dbnum,
                          socket_timeout=SOCKET_TIMEOUT, charset="latin-1",
                          decode_responses=True)
    except ConnectionError as e:
        return {"error": str(e)}
    DB_INDEX = dbnum
    return ctx

def db_find(patt):
    """ Search a pattern inside all kbs. When find it return it.
    """
    for i in range(0, MAX_DBINDEX):
        ctx = kb_connect (i)
        if ctx.keys(patt):
            return ctx

def kb_new():
    """ Return a new kb context to an empty kb.
    """
    ctx = db_find(DBINDEX_NAME)
    for index in range(1, MAX_DBINDEX):
            if try_database_index(ctx, index) == 1:
                ctx = kb_connect(index)
                return ctx

def get_kb_context():
    """ Get redis context if it is already connected or do a connection.
    """
    global REDISCONTEXT
    if REDISCONTEXT is not None:
        return REDISCONTEXT

    REDISCONTEXT = db_find(DBINDEX_NAME)

    if REDISCONTEXT is None:
        print("Problem retrieving Redis Context")
        return 2

    return REDISCONTEXT

def item_get_set(name):
    """ Get all values under a KB elements.
    The right global REDISCONTEXT must be already set.
    """
    ctx = get_kb_context()
    return ctx.smembers(name)

def remove_set_member(key, member):
    """ Remove member of the key set.
    The right global REDISCONTEXT must be already set.
    """
    ctx = get_kb_context()
    ctx.srem(key, member)

def item_get_single(name):
    """ Get a single KB element. The right global REDISCONTEXT must be
    already set.
    """
    ctx = get_kb_context()
    return ctx.srandmember(name)

def item_add_single(name, values):
    """ Add a single KB element with one or more values.
    The right global REDISCONTEXT must be already set.
    """
    ctx = get_kb_context()
    ctx.sadd(name, *set(values))

def item_set_single(name, value):
    """ Set (replace) a new single KB element. The right global
    REDISCONTEXT must be already set.
    """
    ctx = get_kb_context()
    pipe = ctx.pipeline()
    pipe.delete(name)
    pipe.sadd(name, *set(value))
    pipe.execute()

def item_del_single(name):
    """ Delete a single KB element. The right global REDISCONTEXT must be
    already set.
    """
    ctx = get_kb_context()
    ctx.delete(name)

def get_pattern(pattern):
    """ Get all items stored under a given pattern.
    """
    ctx = get_kb_context()
    items = ctx.keys(pattern)

    elem_list = []
    for item in items:
        elem_list.append([item, ctx.smembers(item)])
    return elem_list

def get_elem_pattern_by_index(pattern, index=1):
    """ Get all items with index 'index', stored under
    a given pattern.
    """
    ctx = get_kb_context()
    items = ctx.keys(pattern)

    elem_list = []
    for item in items:
        elem_list.append([item, ctx.lindex(item, index)])
    return elem_list

def release_db(kbindex=0):
    """ Connect to redis and select the db by index.
    Flush db and delete the index from DBINDEX_NAME list.
    """
    if kbindex:
        ctx = kb_connect(kbindex)
        ctx.flushdb()
        ctx = kb_connect()
        ctx.hdel(DBINDEX_NAME, kbindex)

def get_result():
    """ Get and remove the oldest result from the list. """
    ctx = get_kb_context()
    return ctx.rpop("internal/results")

def get_status():
    """ Get and remove the oldest host scan status from the list. """
    ctx = get_kb_context()
    return ctx.rpop("internal/status")

def get_host_scan_scan_start_time():
    """ Get the timestamp of the scan start from redis. """
    ctx = get_kb_context()
    return ctx.rpop("internal/start_time")

def get_host_scan_scan_end_time():
    """ Get the timestamp of the scan end from redis. """
    ctx = get_kb_context()
    return ctx.rpop("internal/end_time")
