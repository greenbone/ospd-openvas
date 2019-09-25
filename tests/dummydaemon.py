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

from unittest.mock import patch

from ospd_openvas.daemon import OSPDopenvas


class DummyDaemon(OSPDopenvas):
    def __init__(self, nvti, redis):

        self.VT = {
            '1.3.6.1.4.1.25623.1.0.100061': {
                'creation_time': '1237458156',
                'custom': {
                    'category': '3',
                    'excluded_keys': 'Settings/disable_cgi_scanning',
                    'family': 'Product detection',
                    'filename': 'mantis_detect.nasl',
                    'required_ports': 'Services/www, 80',
                    'timeout': '0',
                },
                'modification_time': (
                    '1533906565'
                ),
                'name': 'Mantis Detection',
                'qod_type': 'remote_banner',
                'insight': 'some insight',
                'severities': {
                    'severity_base_vector': 'AV:N/AC:L/Au:N/C:N/I:N/A:N',
                    'severity_type': 'cvss_base_v2',
                },
                'solution': 'some solution',
                'solution_type': 'WillNotFix',
                'impact': 'some impact',
                'summary': 'some summary',
                'affected': 'some affection',
                'vt_dependencies': [],
                'vt_params': {
                    '1': {
                        'id': '1',
                        'default': '',
                        'description': 'Description',
                        'name': 'Data length :',
                        'type': 'entry',
                    },
                    '2': {
                        'id': '2',
                        'default': 'no',
                        'description': 'Description',
                        'name': 'Do not randomize the  order  in  which ports are scanned',
                        'type': 'checkbox',
                    },
                },
                'vt_refs': {
                    'bid': [''],
                    'cve': [''],
                    'xref': ['URL:http://www.mantisbt.org/'],
                },
            }
        }

        oids = [['mantis_detect.nasl', '1.3.6.1.4.1.25623.1.0.100061']]
        nvti.get_oids.return_value = oids
        nvti.get_nvt_params.return_value = {
            '1': {
                'id': '1',
                'default': '',
                'description': 'Description',
                'name': 'Data length :',
                'type': 'entry',
            },
            '2': {
                'id': '2',
                'default': 'no',
                'description': 'Description',
                'name': 'Do not randomize the  order  in  which ports are scanned',
                'type': 'checkbox',
            },
        }
        nvti.get_nvt_refs.return_value = {
            'bid': [''],
            'cve': [''],
            'xref': ['URL:http://www.mantisbt.org/'],
        }
        nvti.get_nvt_metadata.return_value = {
            'category': '3',
            'creation_date': '1237458156',
            'cvss_base_vector': 'AV:N/AC:L/Au:N/C:N/I:N/A:N',
            'excluded_keys': 'Settings/disable_cgi_scanning',
            'family': 'Product detection',
            'filename': 'mantis_detect.nasl',
            'last_modification': (
                '1533906565'
            ),
            'name': 'Mantis Detection',
            'qod_type': 'remote_banner',
            'required_ports': 'Services/www, 80',
            'solution': 'some solution',
            'solution_type': 'WillNotFix',
            'impact': 'some impact',
            'insight': 'some insight',
            'summary': ('some summary'),
            'affected': 'some affection',
            'timeout': '0',
        }

        self.openvas_db = redis
        self.nvti = nvti
        with patch('ospd_openvas.daemon.OpenvasDB', return_value=redis):
            with patch('ospd_openvas.daemon.NVTICache', return_value=nvti):
                with patch.object(OSPDopenvas, 'load_vts', return_value=None):
                    super().__init__(niceness=10)
