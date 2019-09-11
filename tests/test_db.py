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

# pylint: disable=unused-argument

""" Unit Test for ospd-openvas """

from unittest import TestCase
from unittest.mock import patch

from redis.exceptions import ConnectionError as RCE

from ospd.errors import RequiredArgument
from ospd_openvas.db import OpenvasDB, time
from ospd_openvas.errors import OspdOpenvasError


@patch('ospd_openvas.db.redis.Redis')
class TestDB(TestCase):
    def setUp(self):
        self.db = OpenvasDB()

    def test_parse_openvas_db_addres(self, mock_redis):
        with self.assertRaises(OspdOpenvasError):
            self.db._parse_openvas_db_address(  # pylint: disable=protected-access
                b'somedata'
            )

    @patch('ospd_openvas.db.subprocess')
    def test_get_db_connection(self, mock_subproc, mock_redis):
        # it is none
        self.assertIsNone(self.db.db_address)
        # set the first time
        mock_subproc.check_output.return_value = 'db_address = /foo/bar'.encode()
        self.db.get_db_connection()
        self.assertEqual(self.db.db_address, "/foo/bar")

        # return immediately because already set
        self.db.get_db_connection()
        self.assertEqual(self.db.db_address, "/foo/bar")

    def test_max_db_index_fail(self, mock_redis):
        mock_redis.config_get.return_value = {}
        with patch.object(OpenvasDB, 'kb_connect', return_value=mock_redis):
            with self.assertRaises(OspdOpenvasError):
                self.db.max_db_index()

    def test_set_ctx_with_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.set_redisctx(None)

    def test_set_ctx(self, mock_redis):
        self.db.set_redisctx(mock_redis)
        self.assertIs(self.db.rediscontext, mock_redis)

    def test_try_db_index_success(self, mock_redis):
        mock_redis.hsetnx.return_value = 1
        ret = self.db.try_database_index(mock_redis, 1)
        self.assertEqual(ret, True)

    def test_try_db_index_no_succes(self, mock_redis):
        mock_redis.hsetnx.return_value = 0
        ret = self.db.try_database_index(mock_redis, 1)
        self.assertEqual(ret, False)

    def test_try_db_index_error(self, mock_redis):
        mock_redis.hsetnx.side_effect = Exception
        with self.assertRaises(OspdOpenvasError):
            self.db.try_database_index(mock_redis, 1)

    def test_kb_connect(self, mock_redis):
        mock_redis.side_effect = RCE
        with patch.object(OpenvasDB, 'get_db_connection', return_value=None):
            with patch.object(time, 'sleep', return_value=None):
                with self.assertRaises(OspdOpenvasError):
                    self.db.kb_connect()

    def test_kb_new_fail(self, mock_redis):
        ret = self.db.kb_new()
        self.assertEqual(ret, None)

    def test_kb_new(self, mock_redis):
        with patch.object(OpenvasDB, 'db_find', return_value=mock_redis):
            with patch.object(
                OpenvasDB, 'try_database_index', return_value=True
            ):
                with patch.object(
                    OpenvasDB, 'kb_connect', return_value=mock_redis
                ):
                    self.db.max_dbindex = 10
                    ret = self.db.kb_new()
        self.assertIs(ret, mock_redis)

    def test_get_kb_context(self, mock_redis):
        self.db.rediscontext = mock_redis
        ret = self.db.get_kb_context()
        self.assertIs(ret, mock_redis)

    def test_get_kb_context_fail(self, mock_redis):
        with patch.object(OpenvasDB, 'db_find', return_value=None):
            with self.assertRaises(OspdOpenvasError):
                self.db.get_kb_context()

    def test_select_kb_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.select_kb(None, 1)

    def test_select_kb_error1(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.select_kb(mock_redis, None)

    def test_select_kb(self, mock_redis):
        mock_redis.execute_command.return_value = mock_redis
        self.db.select_kb(mock_redis, 1, True)
        self.assertEqual(self.db.db_index, '1')
        self.assertIs(self.db.rediscontext, mock_redis)

    def test_get_list_item_fail(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.get_list_item(None)

    def test_get_list_item(self, mock_redis):
        mock_redis.lrange.return_value = ['1234']
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            ret = self.db.get_list_item('name', ctx=None)
        self.assertEqual(ret, ['1234'])

    def test_rm_list_item(self, mock_redis):
        mock_redis.lrem.return_value = 1
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            self.db.remove_list_item('name', '1234', ctx=None)
        mock_redis.lrem.assert_called_once_with('name', count=0, value='1234')

    def test_rm_list_item_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.remove_list_item('1', None)

    def test_rm_list_item_error1(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.remove_list_item(None, '1')

    def test_get_single_item_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.get_single_item(None, '1')

    def test_get_single_item(self, mock_redis):
        mock_redis.lindex.return_value = 'a'
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            self.db.get_single_item('a', ctx=None)
        mock_redis.lindex.assert_called_once_with('a', 0)

    def test_add_single_item(self, mock_redis):
        mock_redis.rpush.return_value = 1
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            self.db.add_single_item('a', ['12'], ctx=None)
        mock_redis.rpush.assert_called_once_with('a', '12')

    def test_add_single_item_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.add_single_item(None, '1')

    def test_add_single_item_error1(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.add_single_item('1', None)

    def test_set_single_item_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.set_single_item(None, '1')

    def test_set_single_item_error1(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.set_single_item('1', None)

    def test_set_single_item(self, mock_redis):
        mock_redis.pipeline.return_value = mock_redis.pipeline
        mock_redis.pipeline.delete.return_value = None
        mock_redis.pipeline.rpush.return_value = None
        mock_redis.execute.return_value = None
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            self.db.set_single_item('a', ['12'], ctx=None)
        mock_redis.pipeline.rpush.assert_called_once_with('a', '12')
        mock_redis.pipeline.delete.assert_called_once_with('a')

    def test_get_pattern(self, mock_redis):
        mock_redis.keys.return_value = ['a', 'b']
        mock_redis.lrange.return_value = [1, 2, 3]
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            ret = self.db.get_pattern('a')
        self.assertEqual(ret, [['a', [1, 2, 3]], ['b', [1, 2, 3]]])

    def test_get_pattern_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.get_pattern(None)

    def test_get_elem_pattern_by_index_error(self, mock_redis):
        with self.assertRaises(RequiredArgument):
            self.db.get_elem_pattern_by_index(None)

    def test_get_elem_pattern_by_index(self, mock_redis):
        mock_redis.keys.return_value = ['aa', 'ab']
        mock_redis.lindex.side_effect = [1, 2]
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            ret = self.db.get_elem_pattern_by_index('a')
        self.assertEqual(ret, [['aa', 1], ['ab', 2]])

    def test_release_db(self, mock_redis):
        mock_redis.delete.return_value = None
        mock_redis.flushdb.return_value = None
        mock_redis.hdel.return_value = 1
        with patch.object(OpenvasDB, 'kb_connect', return_value=mock_redis):
            self.db.release_db(3)
        mock_redis.hdel.assert_called_once_with('GVM.__GlobalDBIndex', 3)

    def test_get_result(self, mock_redis):
        mock_redis.rpop.return_value = 'some result'
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            ret = self.db.get_result()
        self.assertEqual(ret, 'some result')

    def test_get_status(self, mock_redis):
        mock_redis.rpop.return_value = 'some status'
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            ret = self.db.get_status()
        self.assertEqual(ret, 'some status')

    def test_get_stime(self, mock_redis):
        mock_redis.rpop.return_value = 'some start time'
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            ret = self.db.get_host_scan_scan_start_time()
        self.assertEqual(ret, 'some start time')

    def test_get_etime(self, mock_redis):
        mock_redis.rpop.return_value = 'some end time'
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            ret = self.db.get_host_scan_scan_end_time()
        self.assertEqual(ret, 'some end time')

    def test_get_host_ip(self, mock_redis):
        mock_redis.lindex.return_value = '192.168.0.1'
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            ret = self.db.get_host_ip()
        self.assertEqual(ret, '192.168.0.1')
