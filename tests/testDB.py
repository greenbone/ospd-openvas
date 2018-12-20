# -*- coding: utf-8 -*-
# Copyright (C) 2018 Greenbone Networks GmbH
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

""" Unit Test for ospd-openvas """

from unittest import TestCase
from unittest.mock import patch
from ospd_openvas.db import OpenvasDB
from ospd_openvas.errors import OSPDOpenvasError, RequiredArgument


@patch('ospd_openvas.db.redis.Redis')
class TestDB(TestCase):

    def setUp(self):
        self.db = OpenvasDB()

    def test_set_ctx_with_error(self, mock_redis):
        self.assertRaises(RequiredArgument, self.db.set_redisctx, None)

    def test_set_ctx(self, mock_redis):
        self.db.set_redisctx(mock_redis)
        assert self.db.rediscontext == mock_redis

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
        self.assertRaises(OSPDOpenvasError, self.db.try_database_index,
                          mock_redis, 1)

    def test_kb_connect(self, mock_redis):
        mock_redis.side_effect = ConnectionError
        with patch.object(OpenvasDB,
                          'get_db_connection', return_value=None):
            self.assertRaises(OSPDOpenvasError, self.db.kb_connect)

    def test_kb_new_fail(self, mock_redis):
        ret = self.db.kb_new()
        self.assertEqual(ret, None)

    def test_kb_new(self, mock_redis):
        with patch.object(OpenvasDB,
                          'db_find', return_value=mock_redis):
            with patch.object(OpenvasDB,
                              'try_database_index', return_value=True):
                with patch.object(OpenvasDB,
                                  'kb_connect', return_value=mock_redis):
                    self.db.max_dbindex = 10
                    ret = self.db.kb_new()
        assert ret == mock_redis

    def test_get_kb_context(self, mock_redis):
        self.db.rediscontext = mock_redis
        ret = self.db.get_kb_context()
        assert ret == mock_redis

    def test_get_kb_context_fail(self, mock_redis):
        with patch.object(OpenvasDB,
                          'db_find', return_value=None):
            self.assertRaises(OSPDOpenvasError, self.db.get_kb_context)

    def test_select_kb_error(self, mock_redis):
        self.assertRaises(RequiredArgument, self.db.select_kb,
                          None, 1)

    def test_select_kb_error1(self, mock_redis):
        self.assertRaises(RequiredArgument, self.db.select_kb,
                          mock_redis, None)

    def test_select_kb(self, mock_redis):
        mock_redis.execute_command.return_value = mock_redis
        self.db.select_kb(mock_redis, 1, True)
        self.assertEqual(self.db.db_index, "1")
        assert self.db.rediscontext is mock_redis

    def test_get_list_item_fail(self, mock_redis):
        self.assertRaises(RequiredArgument, self.db.get_list_item, None)

    def test_get_list_item(self, mock_redis):
        mock_redis.lrange.return_value = ['1234']
        with patch.object(OpenvasDB,
                          'get_kb_context', return_value=mock_redis):
            ret = self.db.get_list_item("name", ctx=None)
        self.assertEqual(ret, ['1234'])

