# -*- coding: utf-8 -*-
# Copyright (C) 2014-2021 Greenbone AG
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

import logging
import threading
from unittest import TestCase, mock
from typing import Dict, Optional, Iterator

from ospd_openvas.messages.result import ResultMessage
from ospd_openvas.notus import Cache, Notus, NotusResultHandler


class CacheFake(Cache):
    # pylint: disable=super-init-not-called
    def __init__(self):
        self.db = {}
        self.ctx = 'foo'

    def store_advisory(self, oid: str, value: Dict[str, str]):
        self.db[oid] = value

    def exists(self, oid: str) -> bool:
        return True if self.db.get(oid, None) else False

    def get_advisory(self, oid: str) -> Optional[Dict[str, str]]:
        return self.db.get(oid, None)

    def get_keys(self) -> Iterator[str]:
        for key, _ in self.db:
            yield key


class NotusTestCase(TestCase):
    @mock.patch('ospd_openvas.notus.OpenvasDB')
    def test_notus_retrieve(self, mock_openvasdb):
        path_mock = mock.MagicMock()
        redis_mock = mock.MagicMock()
        mock_openvasdb.find_database_by_pattern.return_value = ('foo', 1)
        mock_openvasdb.get_filenames_and_oids.return_value = [
            ('filename', '1.2.3')
        ]
        notus = Notus(path_mock, Cache(redis_mock))
        notus._verifier = lambda _: True  # pylint: disable=protected-access
        oids = [x for x in notus.get_oids()]
        self.assertEqual(len(oids), 1)

    @mock.patch('ospd_openvas.notus.OpenvasDB')
    def test_notus_init(self, mock_openvasdb):
        mock_openvasdb.find_database_by_pattern.return_value = ('foo', 1)
        redis_mock = mock.MagicMock()
        path_mock = mock.MagicMock()
        notus = Notus(path_mock, Cache(redis_mock))
        self.assertEqual(mock_openvasdb.find_database_by_pattern.call_count, 1)
        self.assertEqual(notus.cache.ctx, 'foo')

    @mock.patch('ospd_openvas.notus.OpenvasDB')
    def test_notus_reload(self, mock_openvasdb):
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
        mock_openvasdb.find_database_by_pattern.return_value = ('foo', 1)
        load_into_redis = Notus(path_mock, Cache(redis_mock))
        # pylint: disable=protected-access
        load_into_redis._verifier = lambda _: True
        load_into_redis.reload_cache()
        self.assertEqual(mock_openvasdb.set_single_item.call_count, 1)
        mock_openvasdb.reset_mock()
        do_not_load_into_redis = Notus(path_mock, Cache(redis_mock))
        # pylint: disable=protected-access
        do_not_load_into_redis._verifier = lambda _: False
        do_not_load_into_redis.reload_cache()
        self.assertEqual(mock_openvasdb.set_single_item.call_count, 0)

    def test_notus_qod_type(self):
        path_mock = mock.MagicMock()
        adv_path = mock.MagicMock()
        adv_path.name = "hi"
        adv_path.stem = "family"
        path_mock.glob.return_value = [adv_path]
        adv_path.read_bytes.return_value = b'''
        { 
            "family": "family", 
            "advisories": [ 
                {
                    "oid": "12",
                    "qod_type": "package_unreliable",
                    "severity": {
                        "origin": "NVD",
                        "date": 1505784960,
                        "cvss_v2": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        "cvss_v3": null
                    }
                } 
            ] 
        }'''
        cache_fake = CacheFake()
        notus = Notus(path_mock, cache_fake)
        notus._verifier = lambda _: True  # pylint: disable=protected-access
        notus.reload_cache()
        nm = notus.get_nvt_metadata("12")
        assert nm
        self.assertEqual("package_unreliable", nm.get("qod_type", ""))

    def test_notus_cvss_v2_v3_none(self):
        path_mock = mock.MagicMock()
        adv_path = mock.MagicMock()
        adv_path.name = "hi"
        adv_path.stem = "family"
        path_mock.glob.return_value = [adv_path]
        adv_path.read_bytes.return_value = b'''
        { 
            "family": "family", 
            "advisories": [ 
                {
                    "oid": "12",
                    "severity": {
                        "origin": "NVD",
                        "date": 1505784960,
                        "cvss_v2": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                        "cvss_v3": null
                    }
                } 
            ] 
        }'''
        cache_fake = CacheFake()
        notus = Notus(path_mock, cache_fake)
        notus._verifier = lambda _: True  # pylint: disable=protected-access
        notus.reload_cache()
        nm = notus.get_nvt_metadata("12")
        assert nm
        self.assertEqual(
            "AV:N/AC:M/Au:N/C:C/I:C/A:C", nm.get("severity_vector", "")
        )

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
