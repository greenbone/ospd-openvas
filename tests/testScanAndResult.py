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

""" Test module for scan runs
"""

from __future__ import print_function

import time
import unittest
import xml.etree.ElementTree as ET
import defusedxml.lxml as secET
from defusedxml.common import EntitiesForbidden

from ospd.ospd import OSPDaemon, OSPDError

class Result(object):
    def __init__(self, type_, **kwargs):
        self.result_type = type_
        self.host = ''
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
        OSPDaemon.__init__(self, 'cert', 'key', 'ca')
        self.checkresult = checkresult
        self.results = results

    def check(self):
        return self.checkresults

    @staticmethod
    def get_custom_vt_as_xml_str(vt_id, custom):
        return '<custom><mytest>static test</mytest></custom>'

    @staticmethod
    def get_params_vt_as_xml_str(vt_id, vt_params):
        return ('<vt_params><vt_param id="abc" type="string">'
                '<name>ABC</name><description>Test ABC</description><default>yes</default>'
                '</vt_param>'
                '<vt_param id="def" type="string">'
                '<name>DEF</name><description>Test DEF</description><default>no</default>'
                '</vt_param></vt_params>')

    @staticmethod
    def get_refs_vt_as_xml_str(vt_id, vt_refs):
        response = '<vt_refs><ref type="cve" id="CVE-2010-4480"/>' \
                    '<ref type="url" id="http://example.com"/></vt_refs>'
        return response

    @staticmethod
    def get_dependencies_vt_as_xml_str(vt_id, vt_dependencies):
        response = '<dependencies>' \
                   '<dependency vt_id="1.3.6.1.4.1.25623.1.0.50282" />' \
                   '<dependency vt_id="1.3.6.1.4.1.25623.1.0.50283" />' \
                   '</dependencies>'

        return response

    @staticmethod
    def get_severities_vt_as_xml_str(vt_id, severities):
        response = '<severities><severity cvss_base="5.0" cvss_' \
                   'type="cvss_base_v2">AV:N/AC:L/Au:N/C:N/I:N/' \
                   'A:P</severity></severities>'

        return response

    @staticmethod
    def get_detection_vt_as_xml_str(vt_id, detection=None,
                                    qod_type=None, qod=None):
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
    def get_creation_time_vt_as_xml_str(vt_id, creation_time):
        response = '<creation_time>01-01-1900</creation_time>'

        return response

    @staticmethod
    def get_modification_time_vt_as_xml_str(vt_id, modification_time):
        response = '<modification_time>02-01-1900</modification_time>'

        return response

    def exec_scan(self, scan_id, target):
        time.sleep(0.01)
        for res in self.results:
            if res.result_type == 'log':
                self.add_scan_log(
                    scan_id, res.host or target, res.name, res.value, res.port)
            if res.result_type == 'error':
                self.add_scan_error(
                    scan_id, res.host or target, res.name, res.value, res.port)
            elif res.result_type == 'host-detail':
                self.add_scan_host_detail(
                    scan_id, res.host or target, res.name, res.value)
            elif res.result_type == 'alarm':
                self.add_scan_alarm(
                    scan_id, res.host or target, res.name, res.value,
                    res.port, res.test_id, res.severity, res.qod)
            else:
                raise ValueError(res.result_type)


class FullTest(unittest.TestCase):
    # TODO: There should be a lot more assert in there !

    def testGetDefaultScannerParams(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command('<get_scanner_details />'))
        # The status of the response must be success (i.e. 200)
        self.assertEqual(response.get('status'), '200')
        # The response root element must have the correct name
        self.assertEqual(response.tag, 'get_scanner_details_response')
        # The response must contain a 'scanner_params' element
        self.assertIsNotNone(response.find('scanner_params'))

    def testGetDefaultHelp(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(daemon.handle_command('<help />'))
        self.assertEqual(response.get('status'), '200')
        response = secET.fromstring(
            daemon.handle_command('<help format="xml" />'))
        self.assertEqual(response.get('status'), '200')
        self.assertEqual(response.tag, 'help_response')

    def testGetDefaultScannerVersion(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(daemon.handle_command('<get_version />'))
        self.assertEqual(response.get('status'), '200')
        self.assertIsNotNone(response.find('protocol'))

    def testGetVTs_no_VT(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(daemon.handle_command('<get_vts />'))
        self.assertEqual(response.get('status'), '200')
        self.assertIsNotNone(response.find('vts'))

    def testGetVTs_single_VT(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4', 'A vulnerability test')
        response = secET.fromstring(daemon.handle_command('<get_vts />'))
        self.assertEqual(response.get('status'), '200')
        vts = response.find('vts')
        self.assertIsNotNone(vts.find('vt'))
        vt = vts.find('vt')
        self.assertEqual(vt.get('id'), '1.2.3.4')

    def testGetVTs_multiple_VTs(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4', 'A vulnerability test')
        daemon.add_vt('some id', 'Another vulnerability test')
        daemon.add_vt('123456789', 'Yet another vulnerability test')
        response = secET.fromstring(daemon.handle_command('<get_vts />'))
        self.assertEqual(response.get('status'), '200')
        vts = response.find('vts')
        self.assertIsNotNone(vts.find('vt'))

    def testGetVTs_multiple_VTs_with_custom(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4', 'A vulnerability test')
        daemon.add_vt('some id', 'Another vulnerability test with custom info', {'depencency': '1.2.3.4'})
        daemon.add_vt('123456789', 'Yet another vulnerability test')
        response = secET.fromstring(daemon.handle_command('<get_vts />'))

    def testGetVTs_VTs_with_params(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4', 'A vulnerability test',
                      vt_params="a", custom="b")
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        # The status of the response must be success (i.e. 200)
        self.assertEqual(response.get('status'), '200')
        # The response root element must have the correct name
        self.assertEqual(response.tag, 'get_vts_response')
        # The response must contain a 'scanner_params' element
        self.assertIsNotNone(response.find('vts'))
        vt_params = response[0][0].findall('vt_params')
        self.assertEqual(1, len(vt_params))
        custom = response[0][0].findall('custom')
        self.assertEqual(1, len(custom))
        params = response.findall('vts/vt/vt_params/vt_param')
        self.assertEqual(2, len(params))

    def testGetVTs_VTs_with_refs(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      vt_refs="c")
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        # The status of the response must be success (i.e. 200)
        self.assertEqual(response.get('status'), '200')
        # The response root element must have the correct name
        self.assertEqual(response.tag, 'get_vts_response')
        # The response must contain a 'vts' element
        self.assertIsNotNone(response.find('vts'))
        vt_params = response[0][0].findall('vt_params')
        self.assertEqual(1, len(vt_params))
        custom = response[0][0].findall('custom')
        self.assertEqual(1, len(custom))
        refs = response.findall('vts/vt/vt_refs/ref')
        self.assertEqual(2, len(refs))

    def testGetVTs_VTs_with_dependencies(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      vt_dependencies="c",)
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        deps = response.findall('vts/vt/dependencies/dependency')
        self.assertEqual(2, len(deps))

    def testGetVTs_VTs_with_severities(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      severities="c",)
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        severity = response.findall('vts/vt/severities/severity')
        self.assertEqual(1, len(severity))

    def testGetVTs_VTs_with_detection_qodt(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      detection="c",
                      qod_t="d")
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        detection = response.findall('vts/vt/detection')
        self.assertEqual(1, len(detection))

    def testGetVTs_VTs_with_detection_qodv(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      detection="c",
                      qod_v="d")
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        detection = response.findall('vts/vt/detection')
        self.assertEqual(1, len(detection))

    def testGetVTs_VTs_with_summary(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      summary="c",)
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        summary = response.findall('vts/vt/summary')
        self.assertEqual(1, len(summary))

    def testGetVTs_VTs_with_impact(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      impact="c",)
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        impact = response.findall('vts/vt/impact')
        self.assertEqual(1, len(impact))

    def testGetVTs_VTs_with_affected(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      affected="c",)
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        affect = response.findall('vts/vt/affected')
        self.assertEqual(1, len(affect))

    def testGetVTs_VTs_with_insight(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      insight="c",)
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        insight = response.findall('vts/vt/insight')
        self.assertEqual(1, len(insight))

    def testGetVTs_VTs_with_solution(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      custom="b",
                      solution="c",
                      solution_t="d")
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        solution = response.findall('vts/vt/solution')
        self.assertEqual(1, len(solution))

    def testGetVTs_VTs_with_ctime(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      vt_creation_time='01-01-1900')
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        creation_time = response.findall('vts/vt/creation_time')

        self.assertEqual('<creation_time>01-01-1900</creation_time>',
                         ET.tostring(creation_time[0]).decode('utf-8'))

    def testGetVTs_VTs_with_mtime(self):
        daemon = DummyWrapper([])
        daemon.add_vt('1.2.3.4',
                      'A vulnerability test',
                      vt_params="a",
                      vt_modification_time='02-01-1900')
        response = secET.fromstring(
            daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>'))
        modification_time = response.findall('vts/vt/modification_time')

        self.assertEqual('<modification_time>02-01-1900</modification_time>',
                         ET.tostring(modification_time[0]).decode('utf-8'))

    def testiScanWithError(self):
        daemon = DummyWrapper([
            Result('error', value='something went wrong'),
        ])

        response = secET.fromstring(
            daemon.handle_command('<start_scan target="localhost" ports="80, ' \
                                  '443"><scanner_params /></start_scan>'))
        scan_id = response.findtext('id')
        finished = False
        while not finished:
            response = secET.fromstring(
                daemon.handle_command(
                    '<get_scans scan_id="%s" details="0"/>' % scan_id))
            scans = response.findall('scan')
            self.assertEqual(1, len(scans))
            scan = scans[0]
            if int(scan.get('progress')) != 100:
                self.assertEqual('0', scan.get('end_time'))
                time.sleep(.010)
            else:
                finished = True
        response = secET.fromstring(
            daemon.handle_command('<get_scans scan_id="%s"/>' % scan_id))
        response = secET.fromstring(daemon.handle_command('<get_scans />'))
        response = secET.fromstring(
            daemon.handle_command(
                '<get_scans scan_id="%s" details="1"/>' % scan_id))
        self.assertEqual(response.findtext('scan/results/result'),
                         'something went wrong')

        response = secET.fromstring(
            daemon.handle_command('<delete_scan scan_id="%s" />' % scan_id))
        self.assertEqual(response.get('status'), '200')


    def testGetScanPop(self):
        daemon = DummyWrapper([
            Result('host-detail', value='Some Host Detail'),
        ])

        response = secET.fromstring(daemon.handle_command(
            '<start_scan target="localhost" ports="80, 443">' \
            '<scanner_params /></start_scan>'))
        scan_id = response.findtext('id')
        time.sleep(1)

        response = secET.fromstring(
            daemon.handle_command('<get_scans scan_id="%s"/>' % scan_id))
        self.assertEqual(response.findtext('scan/results/result'),
                         'Some Host Detail')

        response = secET.fromstring(
            daemon.handle_command(
                '<get_scans details="0" pop_results="1"/>'))
        self.assertEqual(response.findtext('scan/results/result'),
                         None)

        response = secET.fromstring(
            daemon.handle_command(
                '<get_scans scan_id="%s" pop_results="1"/>' % scan_id))
        self.assertEqual(response.findtext('scan/results/result'),
                         'Some Host Detail')

        response = secET.fromstring(
            daemon.handle_command(
                '<get_scans scan_id="%s" pop_results="1"/>' % scan_id))
        self.assertNotEqual(response.findtext('scan/results/result'),
                         'Some Host Detail')
        self.assertEqual(response.findtext('scan/results/result'),
                         None)

        while True:
            response = secET.fromstring(
                daemon.handle_command(
                    '<get_scans scan_id="%s" details="0"/>' % scan_id))
            scans = response.findall('scan')
            self.assertEqual(1, len(scans))
            scan = scans[0]
            if int(scan.get('progress')) == 100:
                break

        response = secET.fromstring(
            daemon.handle_command('<delete_scan scan_id="%s" />' % scan_id))
        self.assertEqual(response.get('status'), '200')


    def testStopScan(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command('<start_scan ' \
                                  'target="localhost" ports="80, 443">' \
                                  '<scanner_params /></start_scan>'))
        scan_id = response.findtext('id')

        # Depending on the sistem this test can end with a race condition
        # because the scanner is already stopped when the <stop_scan> command
        # is run.
        time.sleep(3)
        cmd = secET.fromstring('<stop_scan scan_id="%s" />' % scan_id)
        self.assertRaises(OSPDError, daemon.handle_stop_scan_command, cmd)

        cmd = secET.fromstring('<stop_scan />')
        self.assertRaises(OSPDError, daemon.handle_stop_scan_command, cmd)


    def testScanWithVTs(self):
        daemon = DummyWrapper([])
        cmd = secET.fromstring('<start_scan ' \
                               'target="localhost" ports="80, 443">' \
                               '<scanner_params /><vt_selection />' \
                               '</start_scan>')
        self.assertRaises(OSPDError, daemon.handle_start_scan_command, cmd)

        # With one VT, without params
        response = secET.fromstring(
            daemon.handle_command('<start_scan ' \
                                  'target="localhost" ports="80, 443">' \
                                  '<scanner_params /><vt_selection>' \
                                  '<vt_single id="1.2.3.4" />' \
                                  '</vt_selection></start_scan>'))
        scan_id = response.findtext('id')
        time.sleep(0.01)
        self.assertEqual(
            daemon.get_scan_vts(scan_id), {'1.2.3.4': {}, 'vt_groups': []})
        self.assertNotEqual(daemon.get_scan_vts(scan_id), {'1.2.3.6': {}})

        # With out VTS
        response = secET.fromstring(
            daemon.handle_command('<start_scan ' \
                                  'target="localhost" ports="80, 443">' \
                                  '<scanner_params /></start_scan>'))
        scan_id = response.findtext('id')
        time.sleep(0.01)
        self.assertEqual(daemon.get_scan_vts(scan_id), {})

    def testScanWithVTs_and_param(self):
        daemon = DummyWrapper([])

        # Raise because no vt_param id attribute
        cmd = secET.fromstring('<start_scan ' +
                               'target="localhost" ports="80, 443">' \
                               '<scanner_params /><vt_selection><vt_si' \
                               'ngle id="1234"><vt_value>200</vt_value>' \
                               '</vt_single></vt_selection></start_scan>')
        self.assertRaises(OSPDError, daemon.handle_start_scan_command, cmd)

        # No error
        response = secET.fromstring(
            daemon.handle_command('<start_scan ' \
                                  'target="localhost" ports="80, 443">' \
                                  '<scanner_params /><vt_selection><vt' \
                                  '_single id="1234"><vt_value id="ABC">200' \
                                  '</vt_value></vt_single></vt_selection>' \
                                  '</start_scan>'))
        scan_id = response.findtext('id')
        time.sleep(0.01)
        self.assertEqual(daemon.get_scan_vts(scan_id),
                         {'1234': {'ABC': '200'}, 'vt_groups': []})


        # Raise because no vtgroup filter attribute
        cmd = secET.fromstring('<start_scan ' \
                               'target="localhost" ports="80, 443">' \
                               '<scanner_params /><vt_selection><vt_group/>' \
                               '</vt_selection></start_scan>')
        self.assertRaises(OSPDError, daemon.handle_start_scan_command, cmd)

        # No error
        response = secET.fromstring(
            daemon.handle_command('<start_scan ' \
                                  'target="localhost" ports="80, 443">' \
                                  '<scanner_params /><vt_selection>' \
                                  '<vt_group filter="a"/>' \
                                  '</vt_selection></start_scan>'))
        scan_id = response.findtext('id')
        time.sleep(0.01)
        self.assertEqual(daemon.get_scan_vts(scan_id),
                         {'vt_groups': ['a']})


    def testBillonLaughs(self):
        daemon = DummyWrapper([])
        lol = (
            '<?xml version="1.0"?>' \
            '<!DOCTYPE lolz [' \
            ' <!ENTITY lol "lol">' \
            ' <!ELEMENT lolz (#PCDATA)>' \
            ' <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">' \
            ' <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">' \
            ' <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">' \
            ' <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">' \
            ' <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">' \
            ' <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">' \
            ' <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">' \
            ' <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">' \
            ' <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">' \
            ']>')
        self.assertRaises(EntitiesForbidden, daemon.handle_command, lol)

    def testScanMultiTarget(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command('<start_scan>' \
                                  '<scanner_params /><vts><vt id="1.2.3.4" />' \
                                  '</vts>' \
                                  '<targets><target>' \
                                  '<hosts>localhosts</hosts>' \
                                  '<ports>80,443</ports>' \
                                  '</target>' \
                                  '<target><hosts>192.168.0.0/24</hosts>' \
                                  '<ports>22</ports></target></targets>' \
                                  '</start_scan>'))
        self.assertEqual(response.get('status'), '200')


    def testMultiTargetWithCredentials(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan>' \
                '<scanner_params /><vts><vt id="1.2.3.4" />' \
                '</vts>' \
                '<targets><target><hosts>localhosts</hosts>' \
                '<ports>80,443</ports></target><target>' \
                '<hosts>192.168.0.0/24</hosts><ports>22' \
                '</ports><credentials>' \
                '<credential type="up" service="ssh" port="22">' \
                '<username>scanuser</username>' \
                '<password>mypass</password>' \
                '</credential><credential type="up" service="smb">' \
                '<username>smbuser</username>' \
                '<password>mypass</password></credential>' \
                '</credentials>' \
                '</target></targets>' \
                '</start_scan>'))

        self.assertEqual(response.get('status'), '200')
        cred_dict = {'ssh': {'type': 'up', 'password':
                    'mypass', 'port': '22', 'username':
                    'scanuser'}, 'smb': {'type': 'up',
                    'password': 'mypass', 'username': 'smbuser'}}
        scan_id = response.findtext('id')
        response = daemon.get_scan_credentials(scan_id, "192.168.0.0/24")
        self.assertEqual(response, cred_dict)

    def testScanGetTarget(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command('<start_scan>' \
                                  '<scanner_params /><vts><vt id="1.2.3.4" />' \
                                  '</vts>' \
                                  '<targets><target>' \
                                  '<hosts>localhosts</hosts>' \
                                  '<ports>80,443</ports>' \
                                  '</target>' \
                                  '<target><hosts>192.168.0.0/24</hosts>' \
                                  '<ports>22</ports></target></targets>' \
                                  '</start_scan>'))
        scan_id = response.findtext('id')
        response = secET.fromstring(
            daemon.handle_command('<get_scans scan_id="%s"/>' % scan_id))
        scan_res = response.find('scan')
        self.assertEqual(scan_res.get('target'), 'localhosts,192.168.0.0/24')

    def testScanGetLegacyTarget(self):
        daemon = DummyWrapper([])

        response = secET.fromstring(
            daemon.handle_command(
                '<start_scan target="localhosts,192.168.0.0/24" ports="22">' \
                '<scanner_params /><vts><vt id="1.2.3.4" />' \
                '</vts>' \
                '</start_scan>'))
        scan_id = response.findtext('id')
        response = secET.fromstring(
            daemon.handle_command('<get_scans scan_id="%s"/>' % scan_id))
        scan_res = response.find('scan')
        self.assertEqual(scan_res.get('target'), 'localhosts,192.168.0.0/24')

    def testScanMultiTargetParallelWithError(self):
        daemon = DummyWrapper([])
        cmd = secET.fromstring('<start_scan parallel="100a">' \
                               '<scanner_params />' \
                               '<targets><target>' \
                               '<hosts>localhosts</hosts>' \
                               '<ports>22</ports>' \
                               '</target></targets>' \
                               '</start_scan>')
        time.sleep(1)
        self.assertRaises(OSPDError, daemon.handle_start_scan_command, cmd)

    def testScanMultiTargetParallel100(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command('<start_scan parallel="100">' \
                                  '<scanner_params />' \
                                  '<targets><target>' \
                                  '<hosts>localhosts</hosts>' \
                                  '<ports>22</ports>' \
                                  '</target></targets>' \
                                  '</start_scan>'))
        time.sleep(1)
        self.assertEqual(response.get('status'), '200')

    def testProgress(self):
        daemon = DummyWrapper([])
        response = secET.fromstring(
            daemon.handle_command('<start_scan parallel="2">' \
                                  '<scanner_params />' \
                                  '<targets><target>' \
                                  '<hosts>localhost1</hosts>' \
                                  '<ports>22</ports>' \
                                  '</target><target>' \
                                  '<hosts>localhost2</hosts>' \
                                  '<ports>22</ports>' \
                                  '</target></targets>' \
                                  '</start_scan>'))
        scan_id = response.findtext('id')
        daemon.set_scan_target_progress(scan_id, 'localhost1', 75)
        daemon.set_scan_target_progress(scan_id, 'localhost2', 25)
        self.assertEqual(daemon.calculate_progress(scan_id), 50)

    def testSetGetVtsVersion(self):
        daemon = DummyWrapper([])
        daemon.set_vts_version('1234')
        version = daemon.get_vts_version()
        self.assertEqual('1234', version)

    def testSetGetVtsVersion_Error(self):
        daemon = DummyWrapper([])
        self.assertRaises(TypeError, daemon.set_vts_version)
