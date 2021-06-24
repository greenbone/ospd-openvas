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


# pylint: disable=unused-argument

""" Unit Test for ospd-openvas """

import logging

from unittest import TestCase
from unittest.mock import patch, MagicMock

from redis.exceptions import ConnectionError as RCE

from ospd.errors import RequiredArgument
from ospd_openvas.db import OpenvasDB, MainDB, ScanDB, KbDB, DBINDEX_NAME, time
from ospd_openvas.errors import OspdOpenvasError

from tests.helper import assert_called


@patch('ospd_openvas.db.redis.Redis')
class TestOpenvasDB(TestCase):
    @patch('ospd_openvas.db.Openvas')
    def test_get_db_connection(
        self, mock_openvas: MagicMock, mock_redis: MagicMock
    ):
        OpenvasDB._db_address = None  # pylint: disable=protected-access
        mock_settings = mock_openvas.get_settings.return_value
        mock_settings.get.return_value = None

        self.assertIsNone(OpenvasDB.get_database_address())

        # set the first time
        mock_openvas.get_settings.return_value = {'db_address': '/foo/bar'}

        self.assertEqual(OpenvasDB.get_database_address(), "/foo/bar")

        self.assertEqual(mock_openvas.get_settings.call_count, 2)

        # should cache address
        self.assertEqual(OpenvasDB.get_database_address(), "/foo/bar")
        self.assertEqual(mock_openvas.get_settings.call_count, 2)

    def test_create_context_fail(self, mock_redis):
        mock_redis.side_effect = RCE

        logging.Logger.error = MagicMock()

        with patch.object(time, 'sleep', return_value=None):
            with self.assertRaises(SystemExit):
                OpenvasDB.create_context()

        logging.Logger.error.assert_called_with(  # pylint: disable=no-member
            'Redis Error: Not possible to connect to the kb.'
        )

    def test_create_context_success(self, mock_redis):
        ctx = mock_redis.return_value
        ret = OpenvasDB.create_context()
        self.assertIs(ret, ctx)

    def test_select_database_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            OpenvasDB.select_database(None, 1)

        with self.assertRaises(RequiredArgument):
            OpenvasDB.select_database(mock_redis, None)

    def test_select_database(self, mock_redis):
        mock_redis.execute_command.return_value = mock_redis

        OpenvasDB.select_database(mock_redis, 1)

        mock_redis.execute_command.assert_called_with('SELECT 1')

    def test_get_list_item_error(self, mock_redis):
        ctx = mock_redis.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_list_item(None, 'foo')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_list_item(ctx, None)

    def test_get_list_item(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.lrange.return_value = ['1234']

        ret = OpenvasDB.get_list_item(ctx, 'name')

        self.assertEqual(ret, ['1234'])
        assert_called(ctx.lrange)

    def test_get_last_list_item(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.rpop.return_value = 'foo'

        ret = OpenvasDB.get_last_list_item(ctx, 'name')

        self.assertEqual(ret, 'foo')
        ctx.rpop.assert_called_with('name')

    def test_get_last_list_item_error(self, mock_redis):
        ctx = mock_redis.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_last_list_item(ctx, None)

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_last_list_item(None, 'name')

    def test_remove_list_item(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.lrem.return_value = 1

        OpenvasDB.remove_list_item(ctx, 'name', '1234')

        ctx.lrem.assert_called_once_with('name', count=0, value='1234')

    def test_remove_list_item_error(self, mock_redis):
        ctx = mock_redis.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.remove_list_item(None, '1', 'bar')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.remove_list_item(ctx, None, 'bar')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.remove_list_item(ctx, '1', None)

    def test_get_single_item_error(self, mock_redis):
        ctx = mock_redis.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_single_item(None, 'foo')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_single_item(ctx, None)

    def test_get_single_item(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.lindex.return_value = 'a'

        value = OpenvasDB.get_single_item(ctx, 'a')

        self.assertEqual(value, 'a')
        ctx.lindex.assert_called_once_with('a', 0)

    def test_add_single_item(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.rpush.return_value = 1

        OpenvasDB.add_single_item(ctx, 'a', ['12'])

        ctx.rpush.assert_called_once_with('a', '12')

    def test_add_single_item_error(self, mock_redis):
        ctx = mock_redis.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.add_single_item(None, '1', ['12'])

        with self.assertRaises(RequiredArgument):
            OpenvasDB.add_single_item(ctx, None, ['12'])

        with self.assertRaises(RequiredArgument):
            OpenvasDB.add_single_item(ctx, '1', None)

    def test_set_single_item_error(self, mock_redis):
        ctx = mock_redis.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.set_single_item(None, '1', ['12'])

        with self.assertRaises(RequiredArgument):
            OpenvasDB.set_single_item(ctx, None, ['12'])

        with self.assertRaises(RequiredArgument):
            OpenvasDB.set_single_item(ctx, '1', None)

    def test_set_single_item(self, mock_redis):
        ctx = mock_redis.return_value
        pipeline = ctx.pipeline.return_value
        pipeline.delete.return_value = None
        pipeline.rpush.return_value = None
        pipeline.execute.return_value = None

        OpenvasDB.set_single_item(ctx, 'foo', ['bar'])

        pipeline.delete.assert_called_once_with('foo')
        pipeline.rpush.assert_called_once_with('foo', 'bar')
        assert_called(pipeline.execute)

    def test_get_pattern(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.keys.return_value = ['a', 'b']
        ctx.lrange.return_value = [1, 2, 3]

        ret = OpenvasDB.get_pattern(ctx, 'a')

        self.assertEqual(ret, [['a', [1, 2, 3]], ['b', [1, 2, 3]]])

    def test_get_pattern_error(self, mock_redis):
        ctx = mock_redis.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_pattern(None, 'a')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_pattern(ctx, None)

    def test_get_filenames_and_oids_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_filenames_and_oids(None)

    def test_get_filenames_and_oids(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.keys.return_value = ['nvt:1', 'nvt:2']
        ctx.lindex.side_effect = ['aa', 'ab']

        ret = OpenvasDB.get_filenames_and_oids(ctx)

        self.assertEqual(list(ret), [('aa', '1'), ('ab', '2')])

    def test_get_keys_by_pattern_error(self, mock_redis):
        ctx = mock_redis.return_value

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_keys_by_pattern(None, 'a')

        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_keys_by_pattern(ctx, None)

    def test_get_keys_by_pattern(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.keys.return_value = ['nvt:2', 'nvt:1']

        ret = OpenvasDB.get_keys_by_pattern(ctx, 'nvt:*')

        # Return sorted list
        self.assertEqual(ret, ['nvt:1', 'nvt:2'])

    def test_get_key_count(self, mock_redis):
        ctx = mock_redis.return_value

        ctx.keys.return_value = ['aa', 'ab']

        ret = OpenvasDB.get_key_count(ctx, "foo")

        self.assertEqual(ret, 2)
        ctx.keys.assert_called_with('foo')

    def test_get_key_count_with_default_pattern(self, mock_redis):
        ctx = mock_redis.return_value

        ctx.keys.return_value = ['aa', 'ab']

        ret = OpenvasDB.get_key_count(ctx)

        self.assertEqual(ret, 2)
        ctx.keys.assert_called_with('*')

    def test_get_key_count_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            OpenvasDB.get_key_count(None)

    def test_find_database_by_pattern_none(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.keys.return_value = None

        new_ctx, index = OpenvasDB.find_database_by_pattern('foo*', 123)

        self.assertIsNone(new_ctx)
        self.assertIsNone(index)

    def test_find_database_by_pattern(self, mock_redis):
        ctx = mock_redis.return_value

        # keys is called twice per iteration
        ctx.keys.side_effect = [None, None, None, None, True, True]

        new_ctx, index = OpenvasDB.find_database_by_pattern('foo*', 123)

        self.assertEqual(new_ctx, ctx)
        self.assertEqual(index, 2)


@patch('ospd_openvas.db.OpenvasDB')
class ScanDBTestCase(TestCase):
    @patch('ospd_openvas.db.redis.Redis')
    def setUp(self, mock_redis):  # pylint: disable=arguments-differ
        self.ctx = mock_redis.return_value
        self.db = ScanDB(10, self.ctx)

    def test_get_result(self, mock_openvas_db):
        mock_openvas_db.pop_list_items.return_value = [
            'some result',
        ]

        ret = self.db.get_result()

        self.assertEqual(
            ret,
            [
                'some result',
            ],
        )
        mock_openvas_db.pop_list_items.assert_called_with(
            self.ctx, 'internal/results'
        )

    def test_get_status(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'some status'

        ret = self.db.get_status('foo')

        self.assertEqual(ret, 'some status')
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/foo'
        )

    def test_select(self, mock_openvas_db):
        ret = self.db.select(11)

        self.assertIs(ret, self.db)
        self.assertEqual(self.db.index, 11)

        mock_openvas_db.select_database.assert_called_with(self.ctx, 11)

    def test_get_scan_id(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'foo'

        ret = self.db.get_scan_id()

        self.assertEqual(ret, 'foo')
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/scan_id'
        )

    def test_get_scan_status(self, mock_openvas_db):
        mock_openvas_db.get_last_list_item.return_value = 'foo'

        ret = self.db.get_scan_status()

        self.assertEqual(ret, 'foo')
        mock_openvas_db.get_last_list_item.assert_called_with(
            self.ctx, 'internal/status'
        )

    def test_get_host_scan_start_time(self, mock_openvas_db):
        mock_openvas_db.get_last_list_item.return_value = 'some start time'

        ret = self.db.get_host_scan_start_time()

        self.assertEqual(ret, 'some start time')
        mock_openvas_db.get_last_list_item.assert_called_with(
            self.ctx, 'internal/start_time'
        )

    def test_get_host_scan_end_time(self, mock_openvas_db):
        mock_openvas_db.get_last_list_item.return_value = 'some end time'

        ret = self.db.get_host_scan_end_time()

        self.assertEqual(ret, 'some end time')
        mock_openvas_db.get_last_list_item.assert_called_with(
            self.ctx, 'internal/end_time'
        )

    def test_get_host_ip(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = '192.168.0.1'

        ret = self.db.get_host_ip()

        self.assertEqual(ret, '192.168.0.1')
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/ip'
        )

    def test_host_is_finished_false(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'foo'

        ret = self.db.host_is_finished('bar')

        self.assertFalse(ret)
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/bar'
        )

    def test_host_is_finished_true(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'finished'

        ret = self.db.host_is_finished('bar')

        self.assertTrue(ret)
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/bar'
        )

    def test_flush(self, mock_openvas_db):
        self.db.flush()

        self.ctx.flushdb.assert_called_with()


@patch('ospd_openvas.db.OpenvasDB')
class KbDBTestCase(TestCase):
    @patch('ospd_openvas.db.redis.Redis')
    def setUp(self, mock_redis):  # pylint: disable=arguments-differ
        self.ctx = mock_redis.return_value
        self.db = KbDB(10, self.ctx)

    def test_get_result(self, mock_openvas_db):
        mock_openvas_db.pop_list_items.return_value = [
            'some results',
        ]

        ret = self.db.get_result()

        self.assertEqual(
            ret,
            [
                'some results',
            ],
        )
        mock_openvas_db.pop_list_items.assert_called_with(
            self.ctx, 'internal/results'
        )

    def test_get_status(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'some status'

        ret = self.db.get_status('foo')

        self.assertEqual(ret, 'some status')
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/foo'
        )

    def test_flush(self, mock_openvas_db):
        self.db.flush()

        self.ctx.flushdb.assert_called_with()

    def test_add_scan_id(self, mock_openvas_db):
        self.db.add_scan_id('foo', 'bar')

        calls = mock_openvas_db.add_single_item.call_args_list

        call = calls[0]
        kwargs = call[0]

        self.assertEqual(kwargs[1], 'internal/bar')
        self.assertEqual(kwargs[2], ['new'])

        call = calls[1]
        kwargs = call[0]

        self.assertEqual(kwargs[1], 'internal/foo/globalscanid')
        self.assertEqual(kwargs[2], ['bar'])

        call = calls[2]
        kwargs = call[0]

        self.assertEqual(kwargs[1], 'internal/scanid')
        self.assertEqual(kwargs[2], ['bar'])

    def test_add_scan_preferences(self, mock_openvas_db):
        prefs = ['foo', 'bar']

        self.db.add_scan_preferences('foo', prefs)

        mock_openvas_db.add_single_item.assert_called_with(
            self.ctx, 'internal/foo/scanprefs', prefs
        )

    @patch('ospd_openvas.db.OpenvasDB')
    def test_add_credentials_to_scan_preferences(
        self, mock_redis, mock_openvas_db
    ):
        prefs = ['foo', 'bar']

        ctx = mock_redis.return_value
        mock_openvas_db.create_context.return_value = ctx

        self.db.add_credentials_to_scan_preferences('scan_id', prefs)

        mock_openvas_db.create_context.assert_called_with(
            self.db.index, encoding='utf-8'
        )

        mock_openvas_db.add_single_item.assert_called_with(
            ctx, 'internal/scan_id/scanprefs', prefs
        )

    def test_add_scan_process_id(self, mock_openvas_db):
        self.db.add_scan_process_id(123)

        mock_openvas_db.add_single_item.assert_called_with(
            self.ctx, 'internal/ovas_pid', [123]
        )

    def test_get_scan_process_id(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = '123'

        ret = self.db.get_scan_process_id()

        self.assertEqual(ret, '123')
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/ovas_pid'
        )

    def test_remove_scan_database(self, mock_openvas_db):
        scan_db = MagicMock(spec=ScanDB)
        scan_db.index = 123

        self.db.remove_scan_database(scan_db)

        mock_openvas_db.remove_list_item.assert_called_with(
            self.ctx, 'internal/dbindex', 123
        )

    def test_target_is_finished_false(self, mock_openvas_db):
        mock_openvas_db.get_single_item.side_effect = ['bar', 'new']

        ret = self.db.target_is_finished('foo')

        self.assertFalse(ret)

        calls = mock_openvas_db.get_single_item.call_args_list

        call = calls[0]
        args = call[0]

        self.assertEqual(args[1], 'internal/foo/globalscanid')

        call = calls[1]
        args = call[0]

        self.assertEqual(args[1], 'internal/bar')

    def test_target_is_finished_true(self, mock_openvas_db):
        mock_openvas_db.get_single_item.side_effect = ['bar', 'finished']

        ret = self.db.target_is_finished('foo')

        self.assertTrue(ret)

        calls = mock_openvas_db.get_single_item.call_args_list

        call = calls[0]
        args = call[0]

        self.assertEqual(args[1], 'internal/foo/globalscanid')

        call = calls[1]
        args = call[0]

        self.assertEqual(args[1], 'internal/bar')

        mock_openvas_db.get_single_item.side_effect = ['bar', None]

        ret = self.db.target_is_finished('foo')

        self.assertTrue(ret)

    def test_stop_scan(self, mock_openvas_db):
        self.db.stop_scan('foo')

        mock_openvas_db.set_single_item.assert_called_with(
            self.ctx, 'internal/foo', ['stop_all']
        )

    def test_scan_is_stopped_false(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'new'

        ret = self.db.scan_is_stopped('foo')

        self.assertFalse(ret)
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/foo'
        )

    def test_scan_is_stopped_true(self, mock_openvas_db):
        mock_openvas_db.get_single_item.return_value = 'stop_all'

        ret = self.db.scan_is_stopped('foo')

        self.assertTrue(ret)
        mock_openvas_db.get_single_item.assert_called_with(
            self.ctx, 'internal/foo'
        )

    def test_get_scan_databases(self, mock_openvas_db):
        mock_openvas_db.get_list_item.return_value = [
            '4',
            self.db.index,
            '7',
            '11',
        ]

        scan_dbs = self.db.get_scan_databases()

        scan_db = next(scan_dbs)
        self.assertEqual(scan_db.index, '4')

        scan_db = next(scan_dbs)
        self.assertEqual(scan_db.index, '7')

        scan_db = next(scan_dbs)
        self.assertEqual(scan_db.index, '11')

        with self.assertRaises(StopIteration):
            next(scan_dbs)


@patch('ospd_openvas.db.redis.Redis')
class MainDBTestCase(TestCase):
    def test_max_database_index_fail(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.config_get.return_value = {}

        maindb = MainDB(ctx)

        with self.assertRaises(OspdOpenvasError):
            max_db = (  # pylint: disable=unused-variable
                maindb.max_database_index
            )

        ctx.config_get.assert_called_with('databases')

    def test_max_database_index(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.config_get.return_value = {'databases': '123'}

        maindb = MainDB(ctx)

        max_db = maindb.max_database_index

        self.assertEqual(max_db, 123)
        ctx.config_get.assert_called_with('databases')

    def test_try_database_success(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.hsetnx.return_value = 1

        maindb = MainDB(ctx)

        ret = maindb.try_database(1)

        self.assertEqual(ret, True)
        ctx.hsetnx.assert_called_with(DBINDEX_NAME, 1, 1)

    def test_try_database_false(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.hsetnx.return_value = 0

        maindb = MainDB(ctx)

        ret = maindb.try_database(1)

        self.assertEqual(ret, False)
        ctx.hsetnx.assert_called_with(DBINDEX_NAME, 1, 1)

    def test_try_db_index_error(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.hsetnx.side_effect = Exception

        maindb = MainDB(ctx)

        with self.assertRaises(OspdOpenvasError):
            maindb.try_database(1)

    def test_release_database_by_index(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.hdel.return_value = 1

        maindb = MainDB(ctx)

        maindb.release_database_by_index(3)

        ctx.hdel.assert_called_once_with(DBINDEX_NAME, 3)

    def test_release_database(self, mock_redis):
        ctx = mock_redis.return_value
        ctx.hdel.return_value = 1

        db = MagicMock()
        db.index = 3
        maindb = MainDB(ctx)
        maindb.release_database(db)

        ctx.hdel.assert_called_once_with(DBINDEX_NAME, 3)
        db.flush.assert_called_with()

    def test_release(self, mock_redis):
        ctx = mock_redis.return_value

        maindb = MainDB(ctx)
        maindb.release()

        ctx.hdel.assert_called_with(DBINDEX_NAME, maindb.index)
        ctx.flushdb.assert_called_with()

    def test_get_new_kb_database(self, mock_redis):
        ctx = mock_redis.return_value

        maindb = MainDB(ctx)
        maindb._max_dbindex = 123  # pylint: disable=protected-access

        ctx.hsetnx.side_effect = [0, 0, 1]

        kbdb = maindb.get_new_kb_database()

        self.assertEqual(kbdb.index, 3)
        ctx.flushdb.assert_called_once_with()

    def test_get_new_kb_database_none(self, mock_redis):
        ctx = mock_redis.return_value

        maindb = MainDB(ctx)
        maindb._max_dbindex = 3  # pylint: disable=protected-access

        ctx.hsetnx.side_effect = [0, 0, 0]

        kbdb = maindb.get_new_kb_database()

        self.assertIsNone(kbdb)
        ctx.flushdb.assert_not_called()

    @patch('ospd_openvas.db.OpenvasDB')
    def test_find_kb_database_by_scan_id_none(
        self, mock_openvas_db, mock_redis
    ):
        ctx = mock_redis.return_value

        new_ctx = 'bar'  # just some object to compare
        mock_openvas_db.create_context.return_value = new_ctx
        mock_openvas_db.get_single_item.return_value = None

        maindb = MainDB(ctx)
        maindb._max_dbindex = 2  # pylint: disable=protected-access

        scan_id, kbdb = maindb.find_kb_database_by_scan_id('foo')

        mock_openvas_db.get_single_item.assert_called_once_with(
            new_ctx, 'internal/foo/globalscanid'
        )
        self.assertIsNone(scan_id)
        self.assertIsNone(kbdb)

    @patch('ospd_openvas.db.OpenvasDB')
    def test_find_kb_database_by_scan_id(self, mock_openvas_db, mock_redis):
        ctx = mock_redis.return_value

        new_ctx = 'bar'  # just some object to compare
        mock_openvas_db.create_context.return_value = new_ctx
        mock_openvas_db.get_single_item.side_effect = [None, 'ipsum']

        maindb = MainDB(ctx)
        maindb._max_dbindex = 3  # pylint: disable=protected-access

        scan_id, kbdb = maindb.find_kb_database_by_scan_id('foo')

        mock_openvas_db.get_single_item.assert_called_with(
            new_ctx, 'internal/foo/globalscanid'
        )
        self.assertEqual(scan_id, 'ipsum')
        self.assertEqual(kbdb.index, 2)
        self.assertIs(kbdb.ctx, new_ctx)
