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
from ospd_openvas.db import OpenvasDB
from ospd_openvas.nvticache import NVTICache


@patch('ospd_openvas.db.redis.Redis')
class TestNVTICache(TestCase):
    def setUp(self):
        self.db = OpenvasDB()
        self.nvti = NVTICache(self.db)

    def test_get_feed_version(self, mock_redis):
        with patch.object(OpenvasDB, 'db_find', return_value=mock_redis):
            with patch.object(
                OpenvasDB, 'get_single_item', return_value='1234'
            ):
                resp = self.nvti.get_feed_version()
        self.assertEqual(resp, '1234')

    def test_get_oids(self, mock_redis):
        with patch.object(
            OpenvasDB, 'get_elem_pattern_by_index', return_value=['oids']
        ):
            resp = self.nvti.get_oids()
        self.assertEqual(resp, ['oids'])

    def test_parse_metadata_tags(self, mock_redis):
        tags = 'tag1'
        ret = self.nvti._parse_metadata_tags(  # pylint: disable=protected-access
            tags, '1.2.3'
        )
        self.assertEqual(ret, {})

    def test_get_nvt_params(self, mock_redis):
        prefs = ['1|||dns-fuzz.timelimit|||entry|||default']
        prefs1 = ['1|||dns-fuzz.timelimit|||entry|||']

        timeout = '300'
        out_dict = {
            '1': {
                'id': '1',
                'type': 'entry',
                'default': 'default',
                'name': 'dns-fuzz.timelimit',
                'description': 'Description',
            },
            '0': {
                'type': 'entry',
                'id': '0',
                'default': '300',
                'name': 'timeout',
                'description': 'Script Timeout',
            },
        }

        out_dict1 = {
            '1': {
                'id': '1',
                'type': 'entry',
                'default': '',
                'name': 'dns-fuzz.timelimit',
                'description': 'Description',
            },
            '0': {
                'type': 'entry',
                'id': '0',
                'default': '300',
                'name': 'timeout',
                'description': 'Script Timeout',
            },
        }
        with patch.object(OpenvasDB, 'get_kb_context', return_value=mock_redis):
            with patch.object(
                NVTICache, 'get_nvt_timeout', return_value=timeout
            ):
                with patch.object(
                    NVTICache, 'get_nvt_prefs', return_value=prefs
                ):

                    resp = self.nvti.get_nvt_params('1.2.3.4')

                with patch.object(
                    NVTICache, 'get_nvt_prefs', return_value=prefs1
                ):

                    resp1 = self.nvti.get_nvt_params('1.2.3.4')
        self.assertEqual(resp, out_dict)
        self.assertEqual(resp1, out_dict1)

    @patch('ospd_openvas.db.subprocess')
    def test_get_nvt_metadata(self, mock_subps, mock_redis):
        metadata = [
            'mantis_detect.nasl',
            '',
            '',
            'Settings/disable_cgi_scanning',
            '',
            'Services/www, 80',
            'find_service.nasl, http_version.nasl',
            'cvss_base_vector=AV:N/AC:L/Au:N/C:N/I:N'
            '/A:N|last_modification=1533906565'
            '|creation_date=1237458156'
            '|summary=Detects the ins'
            'talled version of\n  Mantis a free popular web-based '
            'bugtracking system.\n\n  This script sends HTTP GET r'
            'equest and try to get the version from the\n  respons'
            'e, and sets the result in KB.|qod_type=remote_banner',
            '',
            '',
            'URL:http://www.mantisbt.org/',
            '3',
            '0',
            'Product detection',
            'Mantis Detection',
        ]

        custom = {
            'category': '3',
            'creation_date': '1237458156',
            'cvss_base_vector': 'AV:N/AC:L/Au:N/C:N/I:N/A:N',
            'dependencies': 'find_service.nasl, http_version.nasl',
            'excluded_keys': 'Settings/disable_cgi_scanning',
            'family': 'Product detection',
            'filename': 'mantis_detect.nasl',
            'last_modification': (
                '1533906565'
            ),
            'name': 'Mantis Detection',
            'qod_type': 'remote_banner',
            'required_ports': 'Services/www, 80',
            'summary': (
                'Detects the installed version of\n  Mantis a '
                'free popular web-based bugtracking system.\n'
                '\n  This script sends HTTP GET request and t'
                'ry to get the version from the\n  response, '
                'and sets the result in KB.'
            ),
            'timeout': '0',
        }

        mock_subps.check_output.return_value = (
            'use_mac_addr = no\ndb_address = '
            '/tmp/redis.sock\ndrop_privileges = no'
        ).encode()

        mock_redis.return_value = mock_redis
        mock_redis.config_get.return_value = {'databases': '513'}
        mock_redis.lrange.return_value = metadata
        mock_redis.keys.return_value = 1

        self.db.db_init()

        resp = self.nvti.get_nvt_metadata('1.2.3.4')
        self.assertEqual(resp, custom)

    @patch('ospd_openvas.db.subprocess')
    def test_get_nvt_metadata_fail(self, mock_subps, mock_redis):
        mock_subps.check_output.return_value = (
            'use_mac_addr = no\ndb_address = '
            '/tmp/redis.sock\ndrop_privileges = no'.encode()
        )

        mock_redis.return_value = mock_redis
        mock_redis.config_get.return_value = {'databases': '513'}
        mock_redis.lrange.return_value = {}
        mock_redis.keys.return_value = 1

        self.db.db_init()

        resp = self.nvti.get_nvt_metadata('1.2.3.4')
        self.assertEqual(resp, None)

    @patch('ospd_openvas.db.subprocess')
    def test_get_nvt_refs(self, mock_subps, mock_redis):
        refs = ['', '', 'URL:http://www.mantisbt.org/']
        out_dict = {
            'cve': [''],
            'bid': [''],
            'xref': ['URL:http://www.mantisbt.org/'],
        }

        mock_subps.check_output.return_value = (
            'use_mac_addr = no\ndb_address = '
            '/tmp/redis.sock\ndrop_privileges = no'
        ).encode()

        mock_redis.return_value = mock_redis
        mock_redis.config_get.return_value = {'databases': '513'}
        mock_redis.lrange.return_value = refs
        mock_redis.keys.return_value = 1

        self.db.db_init()

        resp = self.nvti.get_nvt_refs('1.2.3.4')
        self.assertEqual(resp, out_dict)

    @patch('ospd_openvas.db.subprocess')
    def test_get_nvt_refs_fail(self, mock_subps, mock_redis):
        mock_subps.check_output.return_value = (
            'use_mac_addr = no\ndb_address = '
            '/tmp/redis.sock\ndrop_privileges = no'.encode()
        )

        mock_redis.return_value = mock_redis
        mock_redis.config_get.return_value = {'databases': '513'}
        mock_redis.lrange.return_value = {}
        mock_redis.keys.return_value = 1

        self.db.db_init()

        resp = self.nvti.get_nvt_refs('1.2.3.4')
        self.assertEqual(resp, None)

    def test_get_nvt_prefs(self, mock_redis):
        prefs = ['dns-fuzz.timelimit|||entry|||default']
        mock_redis.lrange.return_value = prefs
        mock_redis.return_value = mock_redis
        resp = self.nvti.get_nvt_prefs(mock_redis(), '1.2.3.4')
        self.assertEqual(resp, prefs)

    def test_get_nvt_timeout(self, mock_redis):
        mock_redis.lindex.return_value = '300'
        mock_redis.return_value = mock_redis
        resp = self.nvti.get_nvt_timeout(mock_redis(), '1.2.3.4')
        self.assertEqual(resp, '300')

    def test_get_nvt_tag(self, mock_redis):
        tag = (
            'last_modification=1533906565'
            '|creation_date=1517443741|cvss_bas'
            'e_vector=AV:N/AC:L/Au:N/C:P/I:P/A:P|solution_type=V'
            'endorFix|qod_type=package|affected=rubygems on Debi'
            'an Linux'
        )

        out_dict = {
            'last_modification': '1533906565',
            'creation_date': '1517443741',
            'cvss_base_vector': 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
            'solution_type': 'VendorFix',
            'qod_type': 'package',
            'affected': 'rubygems on Debian Linux',
        }

        mock_redis.lindex.return_value = tag
        mock_redis.return_value = mock_redis

        resp = self.nvti.get_nvt_tag(mock_redis(), '1.2.3.4')

        self.assertEqual(out_dict, resp)
