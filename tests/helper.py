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

import time
import multiprocessing

from unittest.mock import Mock

from xml.etree import ElementTree as et

from ospd.ospd import OSPDaemon


def assert_called(mock: Mock):
    if hasattr(mock, 'assert_called'):
        return mock.assert_called()

    if not mock.call_count == 1:
        msg = "Expected '%s' to have been called once. Called %s times.%s" % (
            mock._mock_name or 'mock',  # pylint: disable=protected-access
            mock.call_count,
            mock._calls_repr(),  # pylint: disable=protected-access
        )
        raise AssertionError(msg)


class FakePsutil:
    def __init__(self, available=None):
        self.available = available


class FakeStream:
    def __init__(self, return_value=True):
        self.response = b''
        self.return_value = return_value

    def write(self, data):
        self.response = self.response + data
        return self.return_value

    def get_response(self):
        return et.fromstring(self.response)


class FakeDataManager:
    def __init__(self):
        pass

    def dict(self):
        return dict()


class DummyWrapper(OSPDaemon):
    def __init__(self, results, checkresult=True):
        super().__init__()
        self.checkresult = checkresult
        self.results = results
        self.initialized = True
        self.scan_collection.data_manager = FakeDataManager()
        self.scan_collection.file_storage_dir = '/tmp'

    def check(self):
        return self.checkresult

    @staticmethod
    def get_custom_vt_as_xml_str(vt_id, custom):
        return '<custom><mytest>static test</mytest></custom>'

    @staticmethod
    def get_params_vt_as_xml_str(vt_id, vt_params):
        return (
            '<params><param id="abc" type="string">'
            '<name>ABC</name><description>Test ABC</description>'
            '<default>yes</default></param>'
            '<param id="def" type="string">'
            '<name>DEF</name><description>Test DEF</description>'
            '<default>no</default></param></params>'
        )

    @staticmethod
    def get_refs_vt_as_xml_str(vt_id, vt_refs):
        response = (
            '<refs><ref type="cve" id="CVE-2010-4480"/>'
            '<ref type="url" id="http://example.com"/></refs>'
        )
        return response

    @staticmethod
    def get_dependencies_vt_as_xml_str(vt_id, vt_dependencies):
        response = (
            '<dependencies>'
            '<dependency vt_id="1.3.6.1.4.1.25623.1.0.50282" />'
            '<dependency vt_id="1.3.6.1.4.1.25623.1.0.50283" />'
            '</dependencies>'
        )

        return response

    @staticmethod
    def get_severities_vt_as_xml_str(vt_id, severities):
        response = (
            '<severities><severity cvss_base="5.0" cvss_'
            'type="cvss_base_v2">AV:N/AC:L/Au:N/C:N/I:N/'
            'A:P</severity></severities>'
        )

        return response

    @staticmethod
    def get_detection_vt_as_xml_str(
        vt_id, detection=None, qod_type=None, qod=None
    ):
        response = '<detection qod_type="package">some detection</detection>'

        return response

    @staticmethod
    def get_summary_vt_as_xml_str(vt_id, summary):
        response = '<summary>Some summary</summary>'

        return response

    @staticmethod
    def get_affected_vt_as_xml_str(vt_id, affected):
        response = '<affected>Some affected</affected>'

        return response

    @staticmethod
    def get_impact_vt_as_xml_str(vt_id, impact):
        response = '<impact>Some impact</impact>'

        return response

    @staticmethod
    def get_insight_vt_as_xml_str(vt_id, insight):
        response = '<insight>Some insight</insight>'

        return response

    @staticmethod
    def get_solution_vt_as_xml_str(
        vt_id, solution, solution_type=None, solution_method=None
    ):
        response = '<solution>Some solution</solution>'

        return response

    @staticmethod
    def get_creation_time_vt_as_xml_str(
        vt_id, creation_time
    ):  # pylint: disable=arguments-differ, arguments-renamed
        response = '<creation_time>%s</creation_time>' % creation_time

        return response

    @staticmethod
    def get_modification_time_vt_as_xml_str(
        vt_id, modification_time
    ):  # pylint: disable=arguments-differ, arguments-renamed
        response = (
            '<modification_time>%s</modification_time>' % modification_time
        )

        return response

    def exec_scan(self, scan_id):
        time.sleep(0.01)
        for res in self.results:
            if res.result_type == 'log':
                self.add_scan_log(
                    scan_id,
                    res.host,
                    res.hostname,
                    res.name,
                    res.value,
                    res.port,
                )
            if res.result_type == 'error':
                self.add_scan_error(
                    scan_id,
                    res.host,
                    res.hostname,
                    res.name,
                    res.value,
                    res.port,
                )
            elif res.result_type == 'host-detail':
                self.add_scan_host_detail(
                    scan_id, res.host, res.hostname, res.name, res.value
                )
            elif res.result_type == 'alarm':
                self.add_scan_alarm(
                    scan_id,
                    res.host,
                    res.hostname,
                    res.name,
                    res.value,
                    res.port,
                    res.test_id,
                    res.severity,
                    res.qod,
                )
            else:
                raise ValueError(res.result_type)
