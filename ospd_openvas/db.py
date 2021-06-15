# -*- coding: utf-8 -*-
# Copyright (C) 2014-2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


""" Access management for redis-based OpenVAS Scanner Database."""
import logging
import sys
import time

from typing import List, NewType, Optional, Iterable, Iterator, Tuple

import redis

from ospd.errors import RequiredArgument
from ospd_openvas.errors import OspdOpenvasError
from ospd_openvas.openvas import Openvas

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

# Name of the namespace usage bitmap in redis.
DBINDEX_NAME = "GVM.__GlobalDBIndex"

logger = logging.getLogger(__name__)

# Types
RedisCtx = NewType('RedisCtx', redis.Redis)


class OpenvasDB:
    """Class to connect to redis, to perform queries, and to move
    from a KB to another."""

    _db_address = None

    @classmethod
    def get_database_address(cls) -> Optional[str]:
        if not cls._db_address:
            settings = Openvas.get_settings()

            cls._db_address = settings.get('db_address')

        return cls._db_address

    @classmethod
    def create_context(
        cls, dbnum: Optional[int] = 0, encoding: Optional[str] = 'latin-1'
    ) -> RedisCtx:
        """Connect to redis to the given database or to the default db 0 .

        Arguments:
            dbnum: The db number to connect to.
            encoding: The encoding to be used to read and write.

        Return a new redis context on success.
        """
        tries = 5
        while tries:
            try:
                ctx = redis.Redis(
                    unix_socket_path=cls.get_database_address(),
                    db=dbnum,
                    socket_timeout=SOCKET_TIMEOUT,
                    encoding=encoding,
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
            logger.error('Redis Error: Not possible to connect to the kb.')
            sys.exit(1)

        return ctx

    @classmethod
    def find_database_by_pattern(
        cls, pattern: str, max_database_index: int
    ) -> Tuple[Optional[RedisCtx], Optional[int]]:
        """Search a pattern inside all kbs up to max_database_index.

        Returns the redis context for the db and its index as a tuple or
        None, None if the db with the pattern couldn't be found.
        """
        for i in range(0, max_database_index):
            ctx = cls.create_context(i)
            if ctx.keys(pattern):
                return (ctx, i)

        return (None, None)

    @staticmethod
    def select_database(ctx: RedisCtx, kbindex: str):
        """Use an existent redis connection and select a redis kb.

        Arguments:
            ctx: Redis context to use.
            kbindex: The new kb to select
        """
        if not ctx:
            raise RequiredArgument('select_database', 'ctx')
        if not kbindex:
            raise RequiredArgument('select_database', 'kbindex')

        ctx.execute_command('SELECT ' + str(kbindex))

    @staticmethod
    def get_list_item(
        ctx: RedisCtx,
        name: str,
        start: Optional[int] = LIST_FIRST_POS,
        end: Optional[int] = LIST_LAST_POS,
    ) -> Optional[list]:
        """Returns the specified elements from `start` to `end` of the
        list stored as `name`.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            start: first range element to get.
            end: last range element to get.

        Return List specified elements in the key.
        """
        if not ctx:
            raise RequiredArgument('get_list_item', 'ctx')
        if not name:
            raise RequiredArgument('get_list_item', 'name')

        return ctx.lrange(name, start, end)

    @staticmethod
    def get_last_list_item(ctx: RedisCtx, name: str) -> str:
        if not ctx:
            raise RequiredArgument('get_last_list_item', 'ctx')
        if not name:
            raise RequiredArgument('get_last_list_item', 'name')

        return ctx.rpop(name)

    @staticmethod
    def pop_list_items(ctx: RedisCtx, name: str) -> List[str]:
        if not ctx:
            raise RequiredArgument('pop_list_items', 'ctx')
        if not name:
            raise RequiredArgument('pop_list_items', 'name')

        pipe = ctx.pipeline()
        pipe.lrange(name, LIST_FIRST_POS, LIST_LAST_POS)
        pipe.delete(name)
        results, redis_return_code = pipe.execute()

        return results if redis_return_code else []

    @staticmethod
    def get_key_count(ctx: RedisCtx, pattern: Optional[str] = None) -> int:
        """Get the number of keys matching with the pattern.

        Arguments:
            ctx: Redis context to use.
            pattern: pattern used as filter.
        """
        if not pattern:
            pattern = "*"

        if not ctx:
            raise RequiredArgument('get_key_count', 'ctx')

        return len(ctx.keys(pattern))

    @staticmethod
    def remove_list_item(ctx: RedisCtx, key: str, value: str):
        """Remove item from the key list.

        Arguments:
            ctx: Redis context to use.
            key: key name of a list.
            value: Value to be removed from the key.
        """
        if not ctx:
            raise RequiredArgument('remove_list_item ', 'ctx')
        if not key:
            raise RequiredArgument('remove_list_item', 'key')
        if not value:
            raise RequiredArgument('remove_list_item ', 'value')

        ctx.lrem(key, count=LIST_ALL, value=value)

    @staticmethod
    def get_single_item(
        ctx: RedisCtx,
        name: str,
        index: Optional[int] = LIST_FIRST_POS,
    ) -> Optional[str]:
        """Get a single KB element.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            index: index of the element to be return.
                   Defaults to the first element in the list.

        Return the first element of the list or None if the name couldn't be
        found.
        """
        if not ctx:
            raise RequiredArgument('get_single_item', 'ctx')
        if not name:
            raise RequiredArgument('get_single_item', 'name')

        return ctx.lindex(name, index)

    @staticmethod
    def add_single_item(ctx: RedisCtx, name: str, values: Iterable):
        """Add a single KB element with one or more values.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            value: Elements to add to the key.
        """
        if not ctx:
            raise RequiredArgument('add_list_item', 'ctx')
        if not name:
            raise RequiredArgument('add_list_item', 'name')
        if not values:
            raise RequiredArgument('add_list_item', 'value')

        ctx.rpush(name, *set(values))

    @staticmethod
    def set_single_item(ctx: RedisCtx, name: str, value: Iterable):
        """Set (replace) a single KB element.

        Arguments:
            ctx: Redis context to use.
            name: key name of a list.
            value: New elements to add to the key.
        """
        if not ctx:
            raise RequiredArgument('set_single_item', 'ctx')
        if not name:
            raise RequiredArgument('set_single_item', 'name')
        if not value:
            raise RequiredArgument('set_single_item', 'value')

        pipe = ctx.pipeline()
        pipe.delete(name)
        pipe.rpush(name, *set(value))
        pipe.execute()

    @staticmethod
    def get_pattern(ctx: RedisCtx, pattern: str) -> List:
        """Get all items stored under a given pattern.

        Arguments:
            ctx: Redis context to use.
            pattern: key pattern to match.

        Return a list with the elements under the matched key.
        """
        if not ctx:
            raise RequiredArgument('get_pattern', 'ctx')
        if not pattern:
            raise RequiredArgument('get_pattern', 'pattern')

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

    @classmethod
    def get_keys_by_pattern(cls, ctx: RedisCtx, pattern: str) -> List[str]:
        """Get all items with index 'index', stored under
        a given pattern.

        Arguments:
            ctx: Redis context to use.
            pattern: key pattern to match.

        Return a sorted list with the elements under the matched key
        """
        if not ctx:
            raise RequiredArgument('get_elem_pattern_by_index', 'ctx')
        if not pattern:
            raise RequiredArgument('get_elem_pattern_by_index', 'pattern')

        return sorted(ctx.keys(pattern))

    @classmethod
    def get_filenames_and_oids(
        cls,
        ctx: RedisCtx,
    ) -> Iterable[Tuple[str, str]]:
        """Get all items with index 'index', stored under
        a given pattern.

        Arguments:
            ctx: Redis context to use.

        Return an iterable where each single tuple contains the filename
            as first element and the oid as the second one.
        """
        if not ctx:
            raise RequiredArgument('get_filenames_and_oids', 'ctx')

        items = cls.get_keys_by_pattern(ctx, 'nvt:*')

        return ((ctx.lindex(item, 0), item[4:]) for item in items)


class BaseDB:
    def __init__(self, kbindex: int, ctx: Optional[RedisCtx] = None):
        if ctx is None:
            self.ctx = OpenvasDB.create_context(kbindex)
        else:
            self.ctx = ctx

        self.index = kbindex

    def flush(self):
        """ Flush the database """
        self.ctx.flushdb()


class BaseKbDB(BaseDB):
    def _add_single_item(
        self, name: str, values: Iterable, utf8_enc: Optional[bool] = False
    ):
        """Changing the encoding format of an existing redis context
        is not possible. Therefore a new temporary redis context is
        created to store key-values encoded with utf-8."""
        if utf8_enc:
            ctx = OpenvasDB.create_context(self.index, encoding='utf-8')
            OpenvasDB.add_single_item(ctx, name, values)
        else:
            OpenvasDB.add_single_item(self.ctx, name, values)

    def _set_single_item(self, name: str, value: Iterable):
        """Set (replace) a single KB element.

        Arguments:
            name: key name of a list.
            value: New elements to add to the key.
        """
        OpenvasDB.set_single_item(self.ctx, name, value)

    def _get_single_item(self, name: str) -> Optional[str]:
        """Get a single KB element.

        Arguments:
            name: key name of a list.
        """
        return OpenvasDB.get_single_item(self.ctx, name)

    def _get_list_item(
        self,
        name: str,
    ) -> Optional[List]:
        """Returns the specified elements from `start` to `end` of the
        list stored as `name`.

        Arguments:
            name: key name of a list.

        Return List specified elements in the key.
        """
        return OpenvasDB.get_list_item(self.ctx, name)

    def _remove_list_item(self, key: str, value: str):
        """Remove item from the key list.

        Arguments:
            key: key name of a list.
            value: Value to be removed from the key.
        """
        OpenvasDB.remove_list_item(self.ctx, key, value)

    def get_result(self) -> Optional[str]:
        """Get and remove the oldest result from the list.

        Return the oldest scan results
        """
        return OpenvasDB.pop_list_items(self.ctx, "internal/results")

    def get_status(self, openvas_scan_id: str) -> Optional[str]:
        """ Return the status of the host scan """
        return self._get_single_item('internal/{}'.format(openvas_scan_id))

    def __repr__(self):
        return '<{} index={}>'.format(self.__class__.__name__, self.index)


class ScanDB(BaseKbDB):
    """ Database for a scanning a single host """

    def select(self, kbindex: int) -> "ScanDB":
        """Select a redis kb.

        Arguments:
            kbindex: The new kb to select
        """
        OpenvasDB.select_database(self.ctx, kbindex)
        self.index = kbindex
        return self

    def get_scan_id(self):
        return self._get_single_item('internal/scan_id')

    def get_scan_status(self) -> Optional[str]:
        """Get and remove the oldest host scan status from the list.

        Return a string which represents the host scan status.
        """
        return OpenvasDB.get_last_list_item(self.ctx, "internal/status")

    def get_host_ip(self) -> Optional[str]:
        """Get the ip of host_kb.

        Return a string with the ip of the host being scanned.
        """
        return self._get_single_item("internal/ip")

    def get_host_scan_start_time(self) -> Optional[str]:
        """Get the timestamp of the scan start from redis.

        Return a string with the timestamp of the scan start.
        """
        return OpenvasDB.get_last_list_item(self.ctx, "internal/start_time")

    def get_host_scan_end_time(self) -> Optional[str]:
        """Get the timestamp of the scan end from redis.

        Return a string with the timestamp of scan end .
        """
        return OpenvasDB.get_last_list_item(self.ctx, "internal/end_time")

    def host_is_finished(self, openvas_scan_id: str) -> bool:
        """ Returns true if the scan of the host is finished """
        status = self.get_status(openvas_scan_id)
        return status == 'finished'


class KbDB(BaseKbDB):
    def get_scan_databases(self) -> Iterator[ScanDB]:
        """Returns an iterator yielding corresponding ScanDBs

        The returned Iterator can't be converted to an Iterable like a List.
        Each yielded ScanDB must be used independently in a for loop. If the
        Iterator gets converted into an Iterable all returned ScanDBs will use
        the same redis context pointing to the same redis database.
        """
        dbs = self._get_list_item('internal/dbindex')
        scan_db = ScanDB(self.index)
        for kbindex in dbs:
            if kbindex == self.index:
                continue

            yield scan_db.select(kbindex)

    def add_scan_id(self, scan_id: str, openvas_scan_id: str):
        self._add_single_item('internal/{}'.format(openvas_scan_id), ['new'])
        self._add_single_item(
            'internal/{}/globalscanid'.format(scan_id), [openvas_scan_id]
        )
        self._add_single_item('internal/scanid', [openvas_scan_id])

    def add_scan_preferences(self, openvas_scan_id: str, preferences: Iterable):
        self._add_single_item(
            'internal/{}/scanprefs'.format(openvas_scan_id), preferences
        )

    def add_credentials_to_scan_preferences(
        self, openvas_scan_id: str, preferences: Iterable
    ):
        """Force the usage of the utf-8 encoding, since some credentials
        contain special chars not supported by latin-1 encoding."""
        self._add_single_item(
            'internal/{}/scanprefs'.format(openvas_scan_id),
            preferences,
            utf8_enc=True,
        )

    def add_scan_process_id(self, pid: int):
        self._add_single_item('internal/ovas_pid', [pid])

    def get_scan_process_id(self) -> Optional[str]:
        return self._get_single_item('internal/ovas_pid')

    def remove_scan_database(self, scan_db: ScanDB):
        self._remove_list_item('internal/dbindex', scan_db.index)

    def target_is_finished(self, scan_id: str) -> bool:
        """ Check if a target has finished. """

        openvas_scan_id = self._get_single_item(
            'internal/{}/globalscanid'.format(scan_id)
        )
        status = self._get_single_item('internal/{}'.format(openvas_scan_id))

        if status is None:
            logger.info(
                "%s: Target set as finished because redis returned None as "
                "scanner status.",
                scan_id,
            )

        return status == 'finished' or status is None

    def stop_scan(self, openvas_scan_id: str):
        self._set_single_item(
            'internal/{}'.format(openvas_scan_id), ['stop_all']
        )

    def scan_is_stopped(self, openvas_scan_id: str) -> bool:
        """Check if the scan should be stopped"""
        status = self._get_single_item('internal/%s' % openvas_scan_id)
        return status == 'stop_all'


class MainDB(BaseDB):
    """ Main Database """

    DEFAULT_INDEX = 0

    def __init__(self, ctx=None):
        super().__init__(self.DEFAULT_INDEX, ctx)

        self._max_dbindex = None

    @property
    def max_database_index(self):
        """Set the number of databases have been configured into kbr struct."""
        if self._max_dbindex is None:
            resp = self.ctx.config_get('databases')

            if len(resp) == 1:
                self._max_dbindex = int(resp.get('databases'))
            else:
                raise OspdOpenvasError(
                    'Redis Error: Not possible to get max_dbindex.'
                )

        return self._max_dbindex

    def try_database(self, index: int) -> bool:
        """Check if a redis db is already in use. If not, set it
        as in use and return.

        Arguments:
            ctx: Redis object connected to the kb with the
                DBINDEX_NAME key.
            index: Number intended to be used.

        Return True if it is possible to use the db. False if the given db
            number is already in use.
        """
        _in_use = 1
        try:
            resp = self.ctx.hsetnx(DBINDEX_NAME, index, _in_use)
        except:
            raise OspdOpenvasError(
                'Redis Error: Not possible to set %s.' % DBINDEX_NAME
            ) from None

        return resp == 1

    def get_new_kb_database(self) -> Optional[KbDB]:
        """Return a new kb db to an empty kb."""
        for index in range(1, self.max_database_index):
            if self.try_database(index):
                kbdb = KbDB(index)
                kbdb.flush()
                return kbdb

        return None

    def find_kb_database_by_scan_id(
        self, scan_id: str
    ) -> Tuple[Optional[str], Optional["KbDB"]]:
        """Find a kb db by via a global scan id"""
        for index in range(1, self.max_database_index):
            ctx = OpenvasDB.create_context(index)
            openvas_scan_id = OpenvasDB.get_single_item(
                ctx, 'internal/{}/globalscanid'.format(scan_id)
            )
            if openvas_scan_id:
                return (openvas_scan_id, KbDB(index, ctx))

        return (None, None)

    def release_database(self, database: BaseDB):
        self.release_database_by_index(database.index)
        database.flush()

    def release_database_by_index(self, index: int):
        self.ctx.hdel(DBINDEX_NAME, index)

    def release(self):
        self.release_database(self)
