# Copyright (C) 2015-2018 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# pylint: disable=too-many-lines

""" Test module for scan runs
"""

import time
import unittest

from unittest.mock import patch

import xml.etree.ElementTree as ET
import defusedxml.lxml as secET

from defusedxml.common import EntitiesForbidden

from ospd.ospd import OSPDaemon
from ospd.errors import OspdCommandError


class Result(object):
    def __init__(self, type_, **kwargs):
        self.result_type = type_
        self.host = ''
        self.hostname = ''
        self.name = ''
        self.value = ''
        self.port = ''
        self.test_id = ''
        self.severity = ''
        self.qod = ''
        for name, value in kwargs.items():
            setattr(self, name, value)


class DummyWrapper(OSPDaemon):
    def __init__(self, results, checkresult=True):
        super().__init__()
        self.checkresult = checkresult
        self.results = results

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
    def get_solution_vt_as_xml_str(vt_id, solution, solution_type=None):
        response = '<solution>Some solution</solution>'

        return response

    @staticmethod
    def get_creation_time_vt_as_xml_str(
        vt_id, creation_time
    ):  # pylint: disable=arguments-differ
        response = '<creation_time>%s</creation_time>' % creation_time

        return response

    @staticmethod
    def get_modification_time_vt_as_xml_str(
        vt_id, modification_time
    ):  # pylint: disable=arguments-differ
        response = (
            '<modification_time>%s</modification_time>' % modification_time
        )

        return response

    def exec_scan(self, scan_id, target):
        time.sleep(0.01)
        for res in self.results:
            if res.result_type == 'log':
                self.add_scan_log(
                    scan_id,
                    res.host or target,
                    res.hostname,
                    res.name,
                    res.value,
                    res.port,
                )
            if res.result_type == 'error':
                self.add_scan_error(
                    scan_id,
                    res.host or target,
                    res.hostname,
                    res.name,
                    res.value,
                    res.port,
                )
            elif res.result_type == 'host-detail':
                self.add_scan_host_detail(
                    scan_id,
                    res.host or target,
                    res.hostname,
                    res.name,
                    res.value,
                )
            elif res.result_type == 'alarm':
                self.add_scan_alarm(
                    scan_id,
                    res.host or target,
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


class ScanTestCase(unittest.TestCase):
    def test_get_default_scanner_params(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command('<get_scanner_details />')
        )

        # The status of the response must be success (i.e. 200)
        self.assertEqual(response.get('status'), '200')
        # The response root element must have the correct name
        self.assertEqual(response.tag, 'get_scanner_details_response')
        # The response must contain a 'scanner_params' element
        self.assertIsNotNone(response.find('scanner_params'))

    def test_get_default_help(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(daemon.handle_command('<help />'))

        self.assertEqual(response.get('status'), '200')

        response = secET.fromstring(
            daemon.handle_command('<help format="xml" />')
        )

        self.assertEqual(response.get('status'), '200')
        self.assertEqual(response.tag, 'help_response')

    @patch('ospd.ospd.subprocess')
    def test_get_performance(self, mock_subproc):
        daemon = DummyWrapper([])
        mock_subproc.check_output.return_value = b'foo'
        response = secET.fromstring(
            daemon.handle_command(
                '<get_performance start="0" end="0" titles="mem"/>')
        )

        self.assertEqual(response.get('status'), '200')
        self.assertEqual(response.tag, 'get_performance_response')

    def test_get_performance_fail_int(self):
        daemon = DummyWrapper([])
        cmd = secET.fromstring(
            '<get_performance start="a" end="0" titles="mem"/>')

        self.assertRaises(
            OspdCommandError, daemon.handle_get_performance, cmd
        )

    def test_get_performance_fail_regex(self):
        daemon = DummyWrapper([])
        cmd = secET.fromstring(
            '<get_performance start="0" end="0" titles="mem|bar"/>')

        self.assertRaises(
            OspdCommandError, daemon.handle_get_performance, cmd
        )

    def test_get_performance_fail_cmd(self):
        daemon = DummyWrapper([])
        cmd = secET.fromstring(
            '<get_performance start="0" end="0" titles="mem1"/>'
        )
        self.assertRaises(
            OspdCommandError, daemon.handle_get_performance, cmd
        )

    def test_get_default_scanner_version(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(daemon.handle_command('<get_version />'))

        self.assertEqual(response.get('status'), '200')
        self.assertIsNotNone(response.find('protocol'))

    def test_get_vts_no_vt(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(daemon.handle_command('<get_vts />'))

        self.assertEqual(response.get('status'), '200')
        self.assertIsNotNone(response.find('vts'))

    def test_get_vts_single_vt(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4', 'A vulnerability test')
        response = secET.fromstring(daemon.handle_command('<get_vts />'))

        self.assertEqual(response.get('status'), '200')

        vts = response.find('vts')
        self.assertIsNotNone(vts.find('vt'))

        vt = vts.find('vt')
        self.assertEqual(vt.get('id'), '1.2.3.4')

    def test_get_vts_filter_positive(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            vt_modification_time='19000202',
        )

        response = secET.fromstring(
            daemon.handle_command(
                '<get_vts filter="modification_time&gt;19000201"></get_vts>'
            )
        )

        self.assertEqual(response.get('status'), '200')
        vts = response.find('vts')

        vt = vts.find('vt')
        self.assertIsNotNone(vt)
        self.assertEqual(vt.get('id'), '1.2.3.4')

        modification_time = response.findall('vts/vt/modification_time')
        self.assertEqual(
            '<modification_time>19000202</modification_time>',
            ET.tostring(modification_time[0]).decode('utf-8'),
        )

    def test_get_vts_filter_negative(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            vt_modification_time='19000202',
        )

        response = secET.fromstring(
            daemon.handle_command(
                '<get_vts filter="modification_time&lt;19000203"></get_vts>'
            )
        )
        self.assertEqual(response.get('status'), '200')

        vts = response.find('vts')

        vt = vts.find('vt')
        self.assertIsNotNone(vt)
        self.assertEqual(vt.get('id'), '1.2.3.4')

        modification_time = response.findall('vts/vt/modification_time')
        self.assertEqual(
            '<modification_time>19000202</modification_time>',
            ET.tostring(modification_time[0]).decode('utf-8'),
        )

    def test_get_vtss_multiple_vts(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4', 'A vulnerability test')
        daemon.add_vt('1.2.3.5', 'Another vulnerability test')
        daemon.add_vt('123456789', 'Yet another vulnerability test')

        response = secET.fromstring(daemon.handle_command('<get_vts />'))

        self.assertEqual(response.get('status'), '200')

        vts = response.find('vts')
        self.assertIsNotNone(vts.find('vt'))

    def test_get_vts_multiple_vts_with_custom(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4', 'A vulnerability test', custom='b')
        daemon.add_vt(
            '4.3.2.1', 'Another vulnerability test with custom info', custom='b'
        )
        daemon.add_vt('123456789', 'Yet another vulnerability test', custom='b')

        response = secET.fromstring(daemon.handle_command('<get_vts />'))
        custom = response.findall('vts/vt/custom')

        self.assertEqual(3, len(custom))

    def test_get_vts_vts_with_params(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4', 'A vulnerability test', vt_params="a", custom="b"
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )
        # The status of the response must be success (i.e. 200)
        self.assertEqual(response.get('status'), '200')

        # The response root element must have the correct name
        self.assertEqual(response.tag, 'get_vts_response')
        # The response must contain a 'scanner_params' element
        self.assertIsNotNone(response.find('vts'))

        vt_params = response[0][0].findall('params')
        self.assertEqual(1, len(vt_params))

        custom = response[0][0].findall('custom')
        self.assertEqual(1, len(custom))

        params = response.findall('vts/vt/params/param')
        self.assertEqual(2, len(params))

    def test_get_vts_vts_with_refs(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            vt_refs="c",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )
        # The status of the response must be success (i.e. 200)
        self.assertEqual(response.get('status'), '200')

        # The response root element must have the correct name
        self.assertEqual(response.tag, 'get_vts_response')

        # The response must contain a 'vts' element
        self.assertIsNotNone(response.find('vts'))

        vt_params = response[0][0].findall('params')
        self.assertEqual(1, len(vt_params))

        custom = response[0][0].findall('custom')
        self.assertEqual(1, len(custom))

        refs = response.findall('vts/vt/refs/ref')
        self.assertEqual(2, len(refs))

    def test_get_vts_vts_with_dependencies(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            vt_dependencies="c",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        deps = response.findall('vts/vt/dependencies/dependency')
        self.assertEqual(2, len(deps))

    def test_get_vts_vts_with_severities(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            severities="c",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        severity = response.findall('vts/vt/severities/severity')
        self.assertEqual(1, len(severity))

    def test_get_vts_vts_with_detection_qodt(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            detection="c",
            qod_t="d",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        detection = response.findall('vts/vt/detection')
        self.assertEqual(1, len(detection))

    def test_get_vts_vts_with_detection_qodv(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            detection="c",
            qod_v="d",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        detection = response.findall('vts/vt/detection')
        self.assertEqual(1, len(detection))

    def test_get_vts_vts_with_summary(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            summary="c",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        summary = response.findall('vts/vt/summary')
        self.assertEqual(1, len(summary))

    def test_get_vts_vts_with_impact(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            impact="c",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        impact = response.findall('vts/vt/impact')
        self.assertEqual(1, len(impact))

    def test_get_vts_vts_with_affected(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            affected="c",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        affect = response.findall('vts/vt/affected')
        self.assertEqual(1, len(affect))

    def test_get_vts_vts_with_insight(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            insight="c",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        insight = response.findall('vts/vt/insight')
        self.assertEqual(1, len(insight))

    def test_get_vts_vts_with_solution(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            solution="c",
            solution_t="d",
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        solution = response.findall('vts/vt/solution')
        self.assertEqual(1, len(solution))

    def test_get_vts_vts_with_ctime(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            vt_creation_time='01-01-1900',
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        creation_time = response.findall('vts/vt/creation_time')
        self.assertEqual(
            '<creation_time>01-01-1900</creation_time>',
            ET.tostring(creation_time[0]).decode('utf-8'),
        )

    def test_get_vts_vts_with_mtime(self):
        daemon = DummyWrapper([])
        daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            vt_modification_time='02-01-1900',
        )

        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>')
        )

        modification_time = response.findall('vts/vt/modification_time')
        self.assertEqual(
            '<modification_time>02-01-1900</modification_time>',
            ET.tostring(modification_time[0]).decode('utf-8'),
        )

    def test_scan_with_error(self):
        daemon = DummyWrapper([Result('error', value='something went wrong')])

        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan target="localhost" ports="80, '
                '443"><scanner_params /></start_scan>'
            )
        )
        scan_id = response.findtext('id')

        finished = False
        while not finished:
            response = secET.fromstring(
                daemon.handle_command(
                    '<get_scans scan_id="%s" details="1"/>' % scan_id
                )
            )
            scans = response.findall('scan')
            self.assertEqual(1, len(scans))

            scan = scans[0]
            status = scan.get('status')

            if status == "init" or status == "running":
                self.assertEqual('0', scan.get('end_time'))
                time.sleep(0.010)
            else:
                finished = True

        response = secET.fromstring(
            daemon.handle_command(
                '<get_scans scan_id="%s" details="1"/>' % scan_id
            )
        )

        self.assertEqual(
            response.findtext('scan/results/result'), 'something went wrong'
        )

        response = secET.fromstring(
            daemon.handle_command('<delete_scan scan_id="%s" />' % scan_id)
        )

        self.assertEqual(response.get('status'), '200')

    def test_get_scan_pop(self):
        daemon = DummyWrapper([Result('host-detail', value='Some Host Detail')])

        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan target="localhost" ports="80, 443">'
                '<scanner_params /></start_scan>'
            )
        )

        scan_id = response.findtext('id')
        time.sleep(1)

        response = secET.fromstring(
            daemon.handle_command('<get_scans scan_id="%s"/>' % scan_id)
        )
        self.assertEqual(
            response.findtext('scan/results/result'), 'Some Host Detail'
        )

        response = secET.fromstring(
            daemon.handle_command(
                '<get_scans scan_id="%s" pop_results="1"/>' % scan_id
            )
        )
        self.assertEqual(
            response.findtext('scan/results/result'), 'Some Host Detail'
        )

        response = secET.fromstring(
            daemon.handle_command('<get_scans details="0" pop_results="1"/>')
        )
        self.assertEqual(response.findtext('scan/results/result'), None)

    def test_stop_scan(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan '
                'target="localhost" ports="80, 443">'
                '<scanner_params /></start_scan>'
            )
        )
        scan_id = response.findtext('id')

        # Depending on the sistem this test can end with a race condition
        # because the scanner is already stopped when the <stop_scan>
        # command is run.
        time.sleep(3)

        cmd = secET.fromstring('<stop_scan scan_id="%s" />' % scan_id)
        self.assertRaises(
            OspdCommandError, daemon.handle_stop_scan_command, cmd
        )

        cmd = secET.fromstring('<stop_scan />')
        self.assertRaises(
            OspdCommandError, daemon.handle_stop_scan_command, cmd
        )

    def test_scan_with_vts(self):
        daemon = DummyWrapper([])
        cmd = secET.fromstring(
            '<start_scan '
            'target="localhost" ports="80, 443">'
            '<scanner_params /><vt_selection />'
            '</start_scan>'
        )

        with self.assertRaises(OspdCommandError):
            daemon.handle_start_scan_command(cmd)

        # With one vt, without params
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan '
                'target="localhost" ports="80, 443">'
                '<scanner_params /><vt_selection>'
                '<vt_single id="1.2.3.4" />'
                '</vt_selection></start_scan>'
            )
        )
        scan_id = response.findtext('id')
        time.sleep(0.01)

        self.assertEqual(
            daemon.get_scan_vts(scan_id), {'1.2.3.4': {}, 'vt_groups': []}
        )
        self.assertNotEqual(daemon.get_scan_vts(scan_id), {'1.2.3.6': {}})

        # With out vtS
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan '
                'target="localhost" ports="80, 443">'
                '<scanner_params /></start_scan>'
            )
        )

        scan_id = response.findtext('id')
        time.sleep(0.01)
        self.assertEqual(daemon.get_scan_vts(scan_id), {})

    def test_scan_with_vts_and_param(self):
        daemon = DummyWrapper([])

        # Raise because no vt_param id attribute
        cmd = secET.fromstring(
            '<start_scan '
            'target="localhost" ports="80, 443">'
            '<scanner_params /><vt_selection><vt_si'
            'ngle id="1234"><vt_value>200</vt_value>'
            '</vt_single></vt_selection></start_scan>'
        )

        with self.assertRaises(OspdCommandError):
            daemon.handle_start_scan_command(cmd)

        # No error
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan '
                'target="localhost" ports="80, 443">'
                '<scanner_params /><vt_selection><vt'
                '_single id="1234"><vt_value id="ABC">200'
                '</vt_value></vt_single></vt_selection>'
                '</start_scan>'
            )
        )
        scan_id = response.findtext('id')
        time.sleep(0.01)
        self.assertEqual(
            daemon.get_scan_vts(scan_id),
            {'1234': {'ABC': '200'}, 'vt_groups': []},
        )

        # Raise because no vtgroup filter attribute
        cmd = secET.fromstring(
            '<start_scan '
            'target="localhost" ports="80, 443">'
            '<scanner_params /><vt_selection><vt_group/>'
            '</vt_selection></start_scan>'
        )
        self.assertRaises(
            OspdCommandError, daemon.handle_start_scan_command, cmd
        )

        # No error
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan '
                'target="localhost" ports="80, 443">'
                '<scanner_params /><vt_selection>'
                '<vt_group filter="a"/>'
                '</vt_selection></start_scan>'
            )
        )
        scan_id = response.findtext('id')
        time.sleep(0.01)
        self.assertEqual(daemon.get_scan_vts(scan_id), {'vt_groups': ['a']})

    def test_billon_laughs(self):
        # pylint: disable=line-too-long
        daemon = DummyWrapper([])
        lol = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE lolz ['
            ' <!ENTITY lol "lol">'
            ' <!ELEMENT lolz (#PCDATA)>'
            ' <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
            ' <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'
            ' <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
            ' <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
            ' <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">'
            ' <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">'
            ' <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">'
            ' <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">'
            ' <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">'
            ']>'
        )
        self.assertRaises(EntitiesForbidden, daemon.handle_command, lol)

    def test_scan_multi_target(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan>'
                '<scanner_params /><vts><vt id="1.2.3.4" />'
                '</vts>'
                '<targets><target>'
                '<hosts>localhosts</hosts>'
                '<ports>80,443</ports>'
                '</target>'
                '<target><hosts>192.168.0.0/24</hosts>'
                '<ports>22</ports></target></targets>'
                '</start_scan>'
            )
        )
        self.assertEqual(response.get('status'), '200')

    def test_multi_target_with_credentials(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan>'
                '<scanner_params /><vts><vt id="1.2.3.4" />'
                '</vts>'
                '<targets><target><hosts>localhosts</hosts>'
                '<ports>80,443</ports></target><target>'
                '<hosts>192.168.0.0/24</hosts><ports>22'
                '</ports><credentials>'
                '<credential type="up" service="ssh" port="22">'
                '<username>scanuser</username>'
                '<password>mypass</password>'
                '</credential><credential type="up" service="smb">'
                '<username>smbuser</username>'
                '<password>mypass</password></credential>'
                '</credentials>'
                '</target></targets>'
                '</start_scan>'
            )
        )

        self.assertEqual(response.get('status'), '200')

        cred_dict = {
            'ssh': {
                'type': 'up',
                'password': 'mypass',
                'port': '22',
                'username': 'scanuser',
            },
            'smb': {'type': 'up', 'password': 'mypass', 'username': 'smbuser'},
        }
        scan_id = response.findtext('id')
        response = daemon.get_scan_credentials(scan_id, "192.168.0.0/24")
        self.assertEqual(response, cred_dict)

    def test_scan_get_target(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan>'
                '<scanner_params /><vts><vt id="1.2.3.4" />'
                '</vts>'
                '<targets><target>'
                '<hosts>localhosts</hosts>'
                '<ports>80,443</ports>'
                '</target>'
                '<target><hosts>192.168.0.0/24</hosts>'
                '<ports>22</ports></target></targets>'
                '</start_scan>'
            )
        )
        scan_id = response.findtext('id')
        response = secET.fromstring(
            daemon.handle_command('<get_scans scan_id="%s"/>' % scan_id)
        )
        scan_res = response.find('scan')
        self.assertEqual(scan_res.get('target'), 'localhosts,192.168.0.0/24')

    def test_scan_get_exclude_hosts(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan>'
                '<scanner_params /><vts><vt id="1.2.3.4" />'
                '</vts>'
                '<targets><target>'
                '<hosts>192.168.10.20-25</hosts>'
                '<ports>80,443</ports>'
                '<exclude_hosts>192.168.10.23-24'
                '</exclude_hosts>'
                '</target>'
                '<target><hosts>192.168.0.0/24</hosts>'
                '<ports>22</ports></target>'
                '</targets>'
                '</start_scan>'
            )
        )
        scan_id = response.findtext('id')
        time.sleep(1)
        finished = daemon.get_scan_finished_hosts(scan_id)
        self.assertEqual(finished, ['192.168.10.23', '192.168.10.24'])

    def test_scan_multi_target_parallel_with_error(self):
        daemon = DummyWrapper([])
        cmd = secET.fromstring(
            '<start_scan parallel="100a">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhosts</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>'
        )
        time.sleep(1)
        self.assertRaises(
            OspdCommandError, daemon.handle_start_scan_command, cmd
        )

    def test_scan_multi_target_parallel_100(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan parallel="100">'
                '<scanner_params />'
                '<targets><target>'
                '<hosts>localhosts</hosts>'
                '<ports>22</ports>'
                '</target></targets>'
                '</start_scan>'
            )
        )
        time.sleep(1)
        self.assertEqual(response.get('status'), '200')

    def test_progress(self):
        daemon = DummyWrapper([])

        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan parallel="2">'
                '<scanner_params />'
                '<targets><target>'
                '<hosts>localhost1</hosts>'
                '<ports>22</ports>'
                '</target><target>'
                '<hosts>localhost2</hosts>'
                '<ports>22</ports>'
                '</target></targets>'
                '</start_scan>'
            )
        )

        scan_id = response.findtext('id')

        daemon.set_scan_host_progress(scan_id, 'localhost1', 'localhost1', 75)
        daemon.set_scan_host_progress(scan_id, 'localhost2', 'localhost2', 25)

        self.assertEqual(daemon.calculate_progress(scan_id), 50)

    def test_set_get_vts_version(self):
        daemon = DummyWrapper([])
        daemon.set_vts_version('1234')

        version = daemon.get_vts_version()
        self.assertEqual('1234', version)

    def test_set_get_vts_version_error(self):
        daemon = DummyWrapper([])
        self.assertRaises(TypeError, daemon.set_vts_version)

    def test_resume_task(self):
        daemon = DummyWrapper(
            [
                Result(
                    'host-detail', host='localhost', value='Some Host Detail'
                ),
                Result(
                    'host-detail', host='localhost', value='Some Host Detail2'
                ),
            ]
        )

        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan parallel="2">'
                '<scanner_params />'
                '<targets><target>'
                '<hosts>localhost</hosts>'
                '<ports>22</ports>'
                '</target></targets>'
                '</start_scan>'
            )
        )
        scan_id = response.findtext('id')

        time.sleep(3)
        cmd = secET.fromstring('<stop_scan scan_id="%s" />' % scan_id)

        with self.assertRaises(OspdCommandError):
            daemon.handle_stop_scan_command(cmd)

        response = secET.fromstring(
            daemon.handle_command(
                '<get_scans scan_id="%s" details="1"/>' % scan_id
            )
        )

        result = response.findall('scan/results/result')
        self.assertEqual(len(result), 2)

        # Resume the task
        cmd = (
            '<start_scan scan_id="%s" target="localhost" ports="80, 443">'
            '<scanner_params /></start_scan>' % scan_id
        )
        response = secET.fromstring(daemon.handle_command(cmd))

        # Check unfinished host
        self.assertEqual(response.findtext('id'), scan_id)
        self.assertEqual(
            daemon.get_scan_unfinished_hosts(scan_id), ['localhost']
        )

        # Finished the host and check unfinished again.
        daemon.set_scan_host_finished(scan_id, "localhost", "localhost")
        self.assertEqual(daemon.get_scan_unfinished_hosts(scan_id), [])

        # Check finished hosts
        self.assertEqual(
            daemon.scan_collection.get_hosts_finished(scan_id), ['localhost']
        )

        # Check if the result was removed.
        response = secET.fromstring(
            daemon.handle_command(
                '<get_scans scan_id="%s" details="1"/>' % scan_id
            )
        )
        result = response.findall('scan/results/result')
        self.assertEqual(len(result), 0)

    def test_result_order (self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan parallel="1">'
                '<scanner_params />'
                '<targets><target>'
                '<hosts>a</hosts>'
                '<ports>22</ports>'
                '</target></targets>'
                '</start_scan>'
            )
        )

        scan_id = response.findtext('id')

        daemon.add_scan_log(scan_id, host='a', name='a')
        daemon.add_scan_log(scan_id, host='c', name='c')
        daemon.add_scan_log(scan_id, host='b', name='b')
        hosts = ['a','c','b']
        response = secET.fromstring(
            daemon.handle_command('<get_scans details="1"/>'
            )
        )
        results = response.findall("scan/results/")

        for idx, res in enumerate(results):
            att_dict = res.attrib
            self.assertEqual(hosts[idx], att_dict['name'])
