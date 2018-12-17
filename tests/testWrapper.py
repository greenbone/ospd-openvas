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

import subprocess
import unittest
from unittest.mock import patch, create_autospec
from redis import Redis
from ospd_openvas.db import OpenvasDB
from ospd_openvas.nvticache import NVTICache
from ospd_openvas.wrapper import OSPDopenvas, OSPD_PARAMS
from ospd.ospd import OSPDaemon, logger

OSPD_PARAMS_OUT = {
    'auto_enable_dependencies': {
        'type': 'boolean',
        'name': 'auto_enable_dependencies',
        'default': 1,
        'mandatory': 1,
        'description': 'Automatically enable the plugins that are depended on',
    },
    'cgi_path': {
        'type': 'string',
        'name': 'cgi_path',
        'default': '/cgi-bin:/scripts',
        'mandatory': 1,
        'description': 'Look for default CGIs in /cgi-bin and /scripts',
    },
    'checks_read_timeout': {
        'type': 'integer',
        'name': 'checks_read_timeout',
        'default': 5,
        'mandatory': 1,
        'description': ('Number  of seconds that the security checks will ' +
                        'wait for when doing a recv()'),
    },
    'drop_privileges': {
        'type': 'boolean',
        'name': 'drop_privileges',
        'default': 0,
        'mandatory': 1,
        'description': '',
    },
    'network_scan': {
        'type': 'boolean',
        'name': 'network_scan',
        'default': 0,
        'mandatory': 1,
        'description': '',
    },
    'non_simult_ports': {
        'type': 'string',
        'name': 'non_simult_ports',
        'default': '22',
        'mandatory': 1,
        'description': ('Prevent to make two connections on the same given ' +
                        'ports at the same time.'),
    },
    'open_sock_max_attempts': {
        'type': 'integer',
        'name': 'open_sock_max_attempts',
        'default': 5,
        'mandatory': 0,
        'description': ('Number of unsuccessful retries to open the socket ' +
                        'before to set the port as closed.'),
    },
    'timeout_retry': {
        'type': 'integer',
        'name': 'timeout_retry',
        'default': 5,
        'mandatory': 0,
        'description': ('Number of retries when a socket connection attempt ' +
                        'timesout.'),
    },
    'optimize_test': {
        'type': 'integer',
        'name': 'optimize_test',
        'default': 5,
        'mandatory': 0,
        'description': ('By default, openvassd does not trust the remote ' +
                        'host banners.'),
    },
    'plugins_timeout': {
        'type': 'integer',
        'name': 'plugins_timeout',
        'default': 5,
        'mandatory': 0,
        'description': 'This is the maximum lifetime, in seconds of a plugin.',
    },
    'report_host_details': {
        'type': 'boolean',
        'name': 'report_host_details',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'safe_checks': {
        'type': 'boolean',
        'name': 'safe_checks',
        'default': 1,
        'mandatory': 1,
        'description': ('Disable the plugins with potential to crash ' +
                        'the remote services'),
    },
    'scanner_plugins_timeout': {
        'type': 'integer',
        'name': 'scanner_plugins_timeout',
        'default': 36000,
        'mandatory': 1,
        'description': 'Like plugins_timeout, but for ACT_SCANNER plugins.',
    },
    'time_between_request': {
        'type': 'integer',
        'name': 'time_between_request',
        'default': 0,
        'mandatory': 0,
        'description': ('Allow to set a wait time between two actions ' +
                        '(open, send, close).'),
    },
    'unscanned_closed': {
        'type': 'boolean',
        'name': 'unscanned_closed',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'unscanned_closed_udp': {
        'type': 'boolean',
        'name': 'unscanned_closed_udp',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'use_mac_addr': {
        'type': 'boolean',
        'name': 'use_mac_addr',
        'default': 0,
        'mandatory': 0,
        'description': 'To test the local network. ' +
                       'Hosts will be referred to by their MAC address.',
    },
    'vhosts': {
        'type': 'string',
        'name': 'vhosts',
        'default': '',
        'mandatory': 0,
        'description': '',
    },
    'vhosts_ip': {
        'type': 'string',
        'name': 'vhosts_ip',
        'default': '',
        'mandatory': 0,
        'description': '',
    },
}

VT = {
    '1.3.6.1.4.1.25623.1.0.100061': {
        'creation_time': '2009-03-19 11:22:36 +0100 (Thu, 19 Mar 2009)',
        'custom': {'category': '3',
                   'excluded_keys': 'Settings/disable_cgi_scanning',
                   'family': 'Product detection',
                   'filename': 'mantis_detect.nasl',
                   'required_ports': 'Services/www, 80',
                   'timeout': '0'},
        'modification_time': '$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $',
        'name': 'Mantis Detection',
        'qod_type': 'remote_banner',
        'severities': {'severity_base_vector': 'AV:N/AC:L/Au:N/C:N/I:N/A:N',
                       'severity_type': 'cvss_base_v2'},
        'summary': 'Detects the installed version of\n  Mantis a free popular web-based bugtracking system.\n\n  This script sends HTTP GET request and try to get the version from the\n  response, and sets the result in KB.',
        'vt_dependencies': [],
        'vt_params': {},
        'vt_refs': {'bid': [''],
                    'cve': [''],
                    'xref': ['URL:http://www.mantisbt.org/']}}
}


class DummyWrapper(OSPDopenvas):
#    @patch('ospd_openvas.wrapper.NVTICache')
#    @patch('ospd_openvas.wrapper.OpenvasDB')
    def __init__(self, nvti, redis):

        oids = [['mantis_detect.nasl', '1.3.6.1.4.1.25623.1.0.100061']]
        nvti.get_oids.return_value = oids
        nvti.get_nvt_params.return_value = {}
        nvti.get_nvt_refs.return_value = {
            'bid': [''],
            'cve': [''],
            'xref': ['URL:http://www.mantisbt.org/']
        }
        nvti.get_nvt_metadata.return_value = {
            'category': '3',
            'creation_date': '2009-03-19 11:22:36 +0100 (Thu, 19 Mar 2009)',
            'cvss_base_vector': 'AV:N/AC:L/Au:N/C:N/I:N/A:N',
            'excluded_keys': 'Settings/disable_cgi_scanning',
            'family': 'Product detection',
            'filename': 'mantis_detect.nasl',
            'last_modification': (
                '$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $'),
            'name': 'Mantis Detection',
            'qod_type': 'remote_banner',
            'required_ports': 'Services/www, 80',
            'summary': (
                'Detects the installed version of\n  Mantis a free popular '
                'web-based bugtracking system.\n\n  This script sends HTTP '
                'GET request and try to get the version from the\n  respons'
                'e, and sets the result in KB.'),
            'timeout': '0'
        }

        self.openvas_db = redis
        self.nvti = nvti
        super(OSPDopenvas, self).__init__('cert', 'key', 'ca')


class TestOspdOpenvas(unittest.TestCase):

    @patch('ospd_openvas.wrapper.subprocess')
    def test_redis_nvticache_init(self, mock_subproc):
        mock_subproc.check_call.return_value = True
        OSPDopenvas.redis_nvticache_init(self)
        self.assertEqual(mock_subproc.check_call.call_count, 1)

    @patch('ospd_openvas.wrapper.subprocess')
    def test_parse_param(self, mock_subproc):

        mock_subproc.check_output.return_value = (
            'non_simult_ports = 22'.encode())
        OSPDopenvas.parse_param(self)
        self.assertEqual(mock_subproc.check_output.call_count, 1)
        self.assertEqual(OSPD_PARAMS, OSPD_PARAMS_OUT)

    @patch('ospd_openvas.db.OpenvasDB')
    @patch('ospd_openvas.nvticache.NVTICache')
    def test_load_vts(self, mock_nvti, mock_db):
        mock_db.return_value = True
        mock_nvti.return_value = True
        w =  DummyWrapper(mock_nvti, mock_db)
        w.load_vts()

        self.assertEqual(w.vts, VT)
