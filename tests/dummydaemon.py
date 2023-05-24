# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later


from unittest.mock import patch, MagicMock

from xml.etree import ElementTree as et

from ospd_openvas.daemon import OSPDopenvas


class FakeDataManager:
    def __init__(self):
        pass

    def dict(self):
        return dict()


class DummyDaemon(OSPDopenvas):
    VTS = {
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
            'modification_time': '1533906565',
            'name': 'Mantis Detection',
            'qod_type': 'remote_banner',
            'insight': 'some insight',
            'severities': {
                'severity_base_vector': 'AV:N/AC:L/Au:N/C:N/I:N/A:N',
                'severity_type': 'cvss_base_v2',
                'severity_date': '1237458156',
                'severity_origin': 'Greenbone',
            },
            'solution': 'some solution',
            'solution_type': 'WillNotFix',
            'solution_method': 'DebianAPTUpgrade',
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
                    'name': (
                        'Do not randomize the  order  in  which ports are'
                        ' scanned'
                    ),
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

    @patch('ospd_openvas.daemon.NVTICache')
    @patch('ospd_openvas.daemon.MainDB')
    def __init__(
        self, _MainDBClass: MagicMock = None, NvtiClass: MagicMock = None
    ):
        assert _MainDBClass
        assert NvtiClass
        nvti = NvtiClass.return_value
        oids = [['mantis_detect.nasl', '1.3.6.1.4.1.25623.1.0.100061']]
        nvti.notus = None
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
                'name': (
                    'Do not randomize the  order  in  which ports are scanned'
                ),
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
            'last_modification': '1533906565',
            'name': 'Mantis Detection',
            'qod_type': 'remote_banner',
            'required_ports': 'Services/www, 80',
            'solution': 'some solution',
            'solution_type': 'WillNotFix',
            'solution_method': 'DebianAPTUpgrade',
            'impact': 'some impact',
            'insight': 'some insight',
            'summary': 'some summary',
            'affected': 'some affection',
            'timeout': '0',
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
                    'name': (
                        'Do not randomize the  order  in  which ports are'
                        ' scanned'
                    ),
                    'type': 'checkbox',
                },
            },
            'refs': {
                'bid': [''],
                'cve': [''],
                'xref': ['URL:http://www.mantisbt.org/'],
            },
        }
        nvti.get_feed_version.return_value = '123'

        super().__init__(
            niceness=10, lock_file_dir='/tmp', mqtt_broker_address=""
        )

        self.scan_collection.data_manager = FakeDataManager()

    def create_xml_target(self) -> et.Element:
        target = et.fromstring(
            "<target><hosts>192.168.0.1</hosts><ports>80,443</ports></target>"
        )
        return target
