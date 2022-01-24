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

import threading
import logging
from unittest import TestCase, mock
from ospd_openvas.messages.result import ResultMessage

from ospd_openvas.notus import NotusResultHandler, Notus


class NotusTestCase(TestCase):
    def test_notus_retrieve(self):
        path_mock = mock.MagicMock()
        redis_mock = mock.MagicMock()
        redis_mock.scan_iter.return_value = ["internal/notus/advisories/12"]
        redis_mock.lindex.return_value = '{"file_name": "/tmp/something" }'
        notus = Notus(path_mock, redis_mock, lambda _: True)
        oids = [x for x in notus.get_filenames_and_oids()]
        self.assertEqual(len(oids), 1)

    def test_notus_reload(self):
        path_mock = mock.MagicMock()
        adv_path = mock.MagicMock()
        adv_path.name = "hi"
        adv_path.stem = "family"
        path_mock.glob.return_value = [adv_path]
        adv_path.read_bytes.return_value = b'''
        { 
            "family": "family", 
            "qod_type": "remote_app", 
            "advisories": [ 
                { "oid": "12", "file_name": "aha.txt" } 
            ] 
        }'''
        redis_mock = mock.MagicMock()
        load_into_redis = Notus(path_mock, redis_mock, lambda _: True)
        load_into_redis.reload_cache()
        self.assertEqual(redis_mock.lpush.call_count, 1)
        redis_mock.reset_mock()
        do_not_load_into_redis = Notus(path_mock, redis_mock, lambda _: False)
        do_not_load_into_redis.reload_cache()
        self.assertEqual(redis_mock.lpush.call_count, 0)

    def test_notus_fail_cases(self):
        def start(self):
            self.function(*self.args, **self.kwargs)

        mock_report_func = mock.MagicMock(return_value=False)
        logging.Logger.warning = mock.MagicMock()

        notus = NotusResultHandler(mock_report_func)

        res_msg = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            port="42",
            uri='file://foo/bar',
        )

        with mock.patch.object(threading.Timer, 'start', start):
            notus.result_handler(res_msg)

        logging.Logger.warning.assert_called_with(  # pylint: disable=no-member
            "Unable to report %d notus results for scan id %s.", 1, "scan_1"
        )

    def test_notus_success_case(self):
        def start(self):
            self.function(*self.args, **self.kwargs)

        mock_report_func = mock.MagicMock(return_value=True)
        logging.Logger.warning = mock.MagicMock()

        notus = NotusResultHandler(mock_report_func)

        res_msg = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            port="42",
            uri='file://foo/bar',
        )

        with mock.patch.object(threading.Timer, 'start', start):
            notus.result_handler(res_msg)

        logging.Logger.warning.assert_not_called()  # pylint: disable=no-member
