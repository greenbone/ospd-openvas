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

# pylint: disable=too-many-lines

""" Test module for scan runs
"""

import time
import unittest

from unittest.mock import patch, MagicMock, Mock

import logging
import xml.etree.ElementTree as ET

from defusedxml.common import EntitiesForbidden

from ospd.resultlist import ResultList
from ospd.errors import OspdCommandError
from ospd.scan import ScanStatus

from .helper import (
    DummyWrapper,
    assert_called,
    FakeStream,
    FakeDataManager,
    FakePsutil,
)


class FakeStartProcess:
    def __init__(self):
        self.run_mock = MagicMock()
        self.call_mock = MagicMock()

        self.func = None
        self.args = None
        self.kwargs = None

    def __call__(self, func, *, args=None, kwargs=None):
        self.func = func
        self.args = args or []
        self.kwargs = kwargs or {}
        return self.call_mock

    def run(self):
        self.func(*self.args, **self.kwargs)
        return self.run_mock

    def __repr__(self):
        return "<FakeProcess func={} args={} kwargs={}>".format(
            self.func, self.args, self.kwargs
        )


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
        self.uri = ''
        for name, value in kwargs.items():
            setattr(self, name, value)


class ScanTestCase(unittest.TestCase):
    def setUp(self):
        self.daemon = DummyWrapper([])
        self.daemon.scan_collection.datamanager = FakeDataManager()
        self.daemon.scan_collection.file_storage_dir = '/tmp'

    def test_get_default_scanner_params(self):
        fs = FakeStream()

        self.daemon.handle_command('<get_scanner_details />', fs)
        response = fs.get_response()

        # The status of the response must be success (i.e. 200)
        self.assertEqual(response.get('status'), '200')
        # The response root element must have the correct name
        self.assertEqual(response.tag, 'get_scanner_details_response')
        # The response must contain a 'scanner_params' element
        self.assertIsNotNone(response.find('scanner_params'))

    def test_get_default_help(self):
        fs = FakeStream()

        self.daemon.handle_command('<help />', fs)
        response = fs.get_response()
        self.assertEqual(response.get('status'), '200')

        fs = FakeStream()
        self.daemon.handle_command('<help format="xml" />', fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')
        self.assertEqual(response.tag, 'help_response')

    def test_get_default_scanner_version(self):
        fs = FakeStream()
        self.daemon.handle_command('<get_version />', fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')
        self.assertIsNotNone(response.find('protocol'))

    def test_get_vts_no_vt(self):
        fs = FakeStream()

        self.daemon.handle_command('<get_vts />', fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')
        self.assertIsNotNone(response.find('vts'))

    def test_get_vt_xml_no_dict(self):
        single_vt = ('1234', None)
        vt = self.daemon.get_vt_xml(single_vt)
        self.assertFalse(vt.get('id'))

    def test_get_vts_single_vt(self):
        fs = FakeStream()
        self.daemon.add_vt('1.2.3.4', 'A vulnerability test')
        self.daemon.handle_command('<get_vts />', fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')

        vts = response.find('vts')
        self.assertIsNotNone(vts.find('vt'))

        vt = vts.find('vt')
        self.assertEqual(vt.get('id'), '1.2.3.4')

    def test_get_vts_version(self):
        fs = FakeStream()
        self.daemon.add_vt('1.2.3.4', 'A vulnerability test')
        self.daemon.set_vts_version('today')
        self.daemon.handle_command('<get_vts />', fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')

        vts_version = response.find('vts').attrib['vts_version']
        self.assertEqual(vts_version, self.daemon.get_vts_version())

        vts = response.find('vts')
        self.assertIsNotNone(vts.find('vt'))

        vt = vts.find('vt')
        self.assertEqual(vt.get('id'), '1.2.3.4')

    def test_get_vts_version_only(self):
        fs = FakeStream()
        self.daemon.add_vt('1.2.3.4', 'A vulnerability test')
        self.daemon.set_vts_version('today')
        self.daemon.handle_command('<get_vts version_only="1"/>', fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')

        vts_version = response.find('vts').attrib['vts_version']
        self.assertEqual(vts_version, self.daemon.get_vts_version())

        vts = response.find('vts')
        self.assertIsNone(vts.find('vt'))

    def test_get_vts_still_not_init(self):
        fs = FakeStream()
        self.daemon.initialized = False
        self.daemon.handle_command('<get_vts />', fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '400')

    def test_get_help_still_not_init(self):
        fs = FakeStream()
        self.daemon.initialized = False
        self.daemon.handle_command('<help/>', fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')

    def test_get_vts_filter_positive(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            vt_modification_time='19000202',
        )
        fs = FakeStream()

        self.daemon.handle_command(
            '<get_vts filter="modification_time&gt;19000201"></get_vts>', fs
        )
        response = fs.get_response()

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
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            vt_modification_time='19000202',
        )
        fs = FakeStream()
        self.daemon.handle_command(
            '<get_vts filter="modification_time&lt;19000203"></get_vts>', fs
        )
        response = fs.get_response()

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

    def test_get_vts_bad_filter(self):
        fs = FakeStream()
        cmd = '<get_vts filter="modification_time"/>'

        self.assertRaises(OspdCommandError, self.daemon.handle_command, cmd, fs)
        self.assertTrue(self.daemon.vts.is_cache_available)

    def test_get_vtss_multiple_vts(self):
        self.daemon.add_vt('1.2.3.4', 'A vulnerability test')
        self.daemon.add_vt('1.2.3.5', 'Another vulnerability test')
        self.daemon.add_vt('123456789', 'Yet another vulnerability test')

        fs = FakeStream()

        self.daemon.handle_command('<get_vts />', fs)
        response = fs.get_response()
        self.assertEqual(response.get('status'), '200')

        vts = response.find('vts')
        self.assertIsNotNone(vts.find('vt'))

    def test_get_vts_multiple_vts_with_custom(self):
        self.daemon.add_vt('1.2.3.4', 'A vulnerability test', custom='b')
        self.daemon.add_vt(
            '4.3.2.1', 'Another vulnerability test with custom info', custom='b'
        )
        self.daemon.add_vt(
            '123456789', 'Yet another vulnerability test', custom='b'
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts />', fs)
        response = fs.get_response()

        custom = response.findall('vts/vt/custom')

        self.assertEqual(3, len(custom))

    def test_get_vts_vts_with_params(self):
        self.daemon.add_vt(
            '1.2.3.4', 'A vulnerability test', vt_params="a", custom="b"
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

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
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            vt_refs="c",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

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
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            vt_dependencies="c",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)

        response = fs.get_response()

        deps = response.findall('vts/vt/dependencies/dependency')
        self.assertEqual(2, len(deps))

    def test_get_vts_vts_with_severities(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            severities="c",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        severity = response.findall('vts/vt/severities/severity')
        self.assertEqual(1, len(severity))

    def test_get_vts_vts_with_detection_qodt(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            detection="c",
            qod_t="d",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        detection = response.findall('vts/vt/detection')
        self.assertEqual(1, len(detection))

    def test_get_vts_vts_with_detection_qodv(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            detection="c",
            qod_v="d",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        detection = response.findall('vts/vt/detection')
        self.assertEqual(1, len(detection))

    def test_get_vts_vts_with_summary(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            summary="c",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        summary = response.findall('vts/vt/summary')
        self.assertEqual(1, len(summary))

    def test_get_vts_vts_with_impact(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            impact="c",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        impact = response.findall('vts/vt/impact')
        self.assertEqual(1, len(impact))

    def test_get_vts_vts_with_affected(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            affected="c",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        affect = response.findall('vts/vt/affected')
        self.assertEqual(1, len(affect))

    def test_get_vts_vts_with_insight(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            insight="c",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        insight = response.findall('vts/vt/insight')
        self.assertEqual(1, len(insight))

    def test_get_vts_vts_with_solution(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            custom="b",
            solution="c",
            solution_t="d",
            solution_m="e",
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        solution = response.findall('vts/vt/solution')
        self.assertEqual(1, len(solution))

    def test_get_vts_vts_with_ctime(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            vt_creation_time='01-01-1900',
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        creation_time = response.findall('vts/vt/creation_time')
        self.assertEqual(
            '<creation_time>01-01-1900</creation_time>',
            ET.tostring(creation_time[0]).decode('utf-8'),
        )

    def test_get_vts_vts_with_mtime(self):
        self.daemon.add_vt(
            '1.2.3.4',
            'A vulnerability test',
            vt_params="a",
            vt_modification_time='02-01-1900',
        )
        fs = FakeStream()

        self.daemon.handle_command('<get_vts vt_id="1.2.3.4"></get_vts>', fs)
        response = fs.get_response()

        modification_time = response.findall('vts/vt/modification_time')
        self.assertEqual(
            '<modification_time>02-01-1900</modification_time>',
            ET.tostring(modification_time[0]).decode('utf-8'),
        )

    def test_clean_forgotten_scans(self):
        fs = FakeStream()

        self.daemon.handle_command(
            '<start_scan target="localhost" ports="80, '
            '443"><scanner_params /></start_scan>',
            fs,
        )
        response = fs.get_response()

        scan_id = response.findtext('id')

        finished = False

        self.daemon.start_queued_scans()
        while not finished:
            fs = FakeStream()
            self.daemon.handle_command(
                '<get_scans scan_id="%s" details="1"/>' % scan_id, fs
            )
            response = fs.get_response()

            scans = response.findall('scan')
            self.assertEqual(1, len(scans))

            scan = scans[0]

            if scan.get('end_time') != '0':
                finished = True
            else:
                time.sleep(0.01)

            fs = FakeStream()
            self.daemon.handle_command(
                '<get_scans scan_id="%s" details="1"/>' % scan_id, fs
            )
            response = fs.get_response()

        self.assertEqual(
            len(list(self.daemon.scan_collection.ids_iterator())), 1
        )

        # Set an old end_time
        self.daemon.scan_collection.scans_table[scan_id]['end_time'] = 123456
        # Run the check
        self.daemon.clean_forgotten_scans()
        # Not removed
        self.assertEqual(
            len(list(self.daemon.scan_collection.ids_iterator())), 1
        )

        # Set the max time and run again
        self.daemon.scaninfo_store_time = 1
        self.daemon.clean_forgotten_scans()
        # Now is removed
        self.assertEqual(
            len(list(self.daemon.scan_collection.ids_iterator())), 0
        )

    def test_scan_with_error(self):
        fs = FakeStream()

        self.daemon.handle_command(
            '<start_scan target="localhost" ports="80, '
            '443"><scanner_params /></start_scan>',
            fs,
        )

        response = fs.get_response()
        scan_id = response.findtext('id')
        finished = False
        self.daemon.start_queued_scans()
        self.daemon.add_scan_error(
            scan_id, host='a', value='something went wrong'
        )

        while not finished:
            fs = FakeStream()
            self.daemon.handle_command(
                '<get_scans scan_id="%s" details="1"/>' % scan_id, fs
            )
            response = fs.get_response()

            scans = response.findall('scan')
            self.assertEqual(1, len(scans))

            scan = scans[0]
            status = scan.get('status')

            if status == "init" or status == "running":
                self.assertEqual('0', scan.get('end_time'))
                time.sleep(0.010)
            else:
                finished = True

            fs = FakeStream()

            self.daemon.handle_command(
                '<get_scans scan_id="%s" details="1"/>' % scan_id, fs
            )
            response = fs.get_response()

        self.assertEqual(
            response.findtext('scan/results/result'), 'something went wrong'
        )
        fs = FakeStream()
        self.daemon.handle_command('<delete_scan scan_id="%s" />' % scan_id, fs)
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')

    def test_get_scan_pop(self):
        fs = FakeStream()

        self.daemon.handle_command(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params /></start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

        scan_id = response.findtext('id')
        self.daemon.add_scan_host_detail(
            scan_id, host='a', value='Some Host Detail'
        )

        time.sleep(1)

        fs = FakeStream()
        self.daemon.handle_command('<get_scans scan_id="%s"/>' % scan_id, fs)
        response = fs.get_response()

        self.assertEqual(
            response.findtext('scan/results/result'), 'Some Host Detail'
        )
        fs = FakeStream()
        self.daemon.handle_command(
            '<get_scans scan_id="%s" pop_results="1"/>' % scan_id, fs
        )
        response = fs.get_response()

        self.assertEqual(
            response.findtext('scan/results/result'), 'Some Host Detail'
        )

        fs = FakeStream()
        self.daemon.handle_command(
            '<get_scans scan_id="%s" details="0" pop_results="1"/>' % scan_id,
            fs,
        )
        response = fs.get_response()

        self.assertEqual(response.findtext('scan/results/result'), None)

    def test_get_scan_pop_max_res(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params /></start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()
        scan_id = response.findtext('id')

        self.daemon.add_scan_log(scan_id, host='a', name='a')
        self.daemon.add_scan_log(scan_id, host='c', name='c')
        self.daemon.add_scan_log(scan_id, host='b', name='b')

        fs = FakeStream()
        self.daemon.handle_command(
            '<get_scans scan_id="%s" pop_results="1" max_results="1"/>'
            % scan_id,
            fs,
        )

        response = fs.get_response()

        self.assertEqual(len(response.findall('scan/results/result')), 1)

        fs = FakeStream()
        self.daemon.handle_command(
            '<get_scans scan_id="%s" pop_results="1"/>' % scan_id, fs
        )
        response = fs.get_response()
        self.assertEqual(len(response.findall('scan/results/result')), 2)

    def test_get_scan_results_clean(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params /></start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()
        scan_id = response.findtext('id')

        self.daemon.add_scan_log(scan_id, host='a', name='a')
        self.daemon.add_scan_log(scan_id, host='c', name='c')
        self.daemon.add_scan_log(scan_id, host='b', name='b')

        fs = FakeStream()
        self.daemon.handle_command(
            '<get_scans scan_id="%s" pop_results="1"/>' % scan_id, fs
        )

        res_len = len(
            self.daemon.scan_collection.scans_table[scan_id]['results']
        )
        self.assertEqual(res_len, 0)

        res_len = len(
            self.daemon.scan_collection.scans_table[scan_id]['temp_results']
        )
        self.assertEqual(res_len, 0)

    def test_get_scan_results_restore(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params /></start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()
        scan_id = response.findtext('id')

        self.daemon.add_scan_log(scan_id, host='a', name='a')
        self.daemon.add_scan_log(scan_id, host='c', name='c')
        self.daemon.add_scan_log(scan_id, host='b', name='b')

        fs = FakeStream(return_value=False)
        self.daemon.handle_command(
            '<get_scans scan_id="%s" pop_results="1"/>' % scan_id, fs
        )

        res_len = len(
            self.daemon.scan_collection.scans_table[scan_id]['results']
        )
        self.assertEqual(res_len, 3)

        res_len = len(
            self.daemon.scan_collection.scans_table[scan_id]['temp_results']
        )
        self.assertEqual(res_len, 0)

    def test_billon_laughs(self):
        # pylint: disable=line-too-long

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
        fs = FakeStream()
        self.assertRaises(
            EntitiesForbidden, self.daemon.handle_command, lol, fs
        )

    def test_target_with_credentials(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets><target>'
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
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

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
        response = self.daemon.get_scan_credentials(scan_id)
        self.assertEqual(response, cred_dict)

    def test_target_with_credential_empty_community(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets><target>'
            '<hosts>192.168.0.0/24</hosts><ports>22'
            '</ports><credentials>'
            '<credential type="up" service="snmp">'
            '<community></community></credential>'
            '</credentials>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

        self.assertEqual(response.get('status'), '200')

        cred_dict = {'snmp': {'type': 'up', 'community': ''}}
        scan_id = response.findtext('id')
        response = self.daemon.get_scan_credentials(scan_id)
        self.assertEqual(response, cred_dict)

    def test_scan_get_target(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets><target>'
            '<hosts>localhosts,192.168.0.0/24</hosts>'
            '<ports>80,443</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()
        scan_id = response.findtext('id')

        fs = FakeStream()
        self.daemon.handle_command('<get_scans scan_id="%s"/>' % scan_id, fs)
        response = fs.get_response()

        scan_res = response.find('scan')
        self.assertEqual(scan_res.get('target'), 'localhosts,192.168.0.0/24')

    def test_scan_get_target_options(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets>'
            '<target><hosts>192.168.0.1</hosts>'
            '<ports>22</ports><alive_test>0</alive_test></target>'
            '</targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()

        scan_id = response.findtext('id')
        time.sleep(1)
        target_options = self.daemon.get_scan_target_options(scan_id)
        self.assertEqual(target_options, {'alive_test': '0'})

    def test_scan_get_target_options_alive_test_methods(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets>'
            '<target><hosts>192.168.0.1</hosts>'
            '<ports>22</ports>'
            '<alive_test_methods>'
            '<icmp>1</icmp>'
            '<tcp_syn>1</tcp_syn>'
            '<tcp_ack>1</tcp_ack>'
            '<arp>1</arp>'
            '<consider_alive>1</consider_alive>'
            '</alive_test_methods>'
            '</target>'
            '</targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()

        scan_id = response.findtext('id')
        time.sleep(1)
        target_options = self.daemon.get_scan_target_options(scan_id)
        self.assertEqual(
            target_options,
            {
                'alive_test_methods': '1',
                'icmp': '1',
                'tcp_syn': '1',
                'tcp_ack': '1',
                'arp': '1',
                'consider_alive': '1',
            },
        )

    def test_scan_get_target_options_alive_test_methods_dont_add_empty_or_missing(  # pylint: disable=line-too-long
        self,
    ):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets>'
            '<target><hosts>192.168.0.1</hosts>'
            '<ports>22</ports>'
            '<alive_test_methods>'
            '<icmp>1</icmp>'
            '<arp></arp>'
            '<consider_alive></consider_alive>'
            '</alive_test_methods>'
            '</target>'
            '</targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()

        scan_id = response.findtext('id')
        time.sleep(1)
        target_options = self.daemon.get_scan_target_options(scan_id)
        self.assertEqual(
            target_options, {'alive_test_methods': '1', 'icmp': '1'}
        )

    def test_progress(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

        scan_id = response.findtext('id')
        self.daemon.set_scan_host_progress(scan_id, 'localhost1', 75)
        self.daemon.set_scan_host_progress(scan_id, 'localhost2', 25)

        self.assertEqual(
            self.daemon.scan_collection.calculate_target_progress(scan_id), 50
        )

    def test_progress_all_host_dead(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

        scan_id = response.findtext('id')
        self.daemon.set_scan_host_progress(scan_id, 'localhost1', -1)
        self.daemon.set_scan_host_progress(scan_id, 'localhost2', -1)

        self.daemon.sort_host_finished(scan_id, ['localhost1', 'localhost2'])
        self.assertEqual(
            self.daemon.scan_collection.calculate_target_progress(scan_id), 100
        )

    @patch('ospd.ospd.os')
    def test_interrupted_scan(self, mock_os):
        mock_os.setsid.return_value = None
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2, localhost3, localhost4</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()
        scan_id = response.findtext('id')

        self.daemon.exec_scan = Mock(return_value=None)
        self.daemon.set_scan_host_progress(scan_id, 'localhost1', 5)
        self.daemon.set_scan_host_progress(scan_id, 'localhost2', 14)
        while self.daemon.get_scan_status(scan_id) == ScanStatus.INIT:
            fs = FakeStream()
            self.daemon.handle_command(
                '<get_scans scan_id="%s" details="0" progress="0"/>' % scan_id,
                fs,
            )
        response = fs.get_response()
        status = response.find('scan').attrib['status']

        self.assertEqual(status, ScanStatus.INTERRUPTED.name.lower())

    def test_sort_host_finished(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2, localhost3, localhost4</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()

        scan_id = response.findtext('id')
        self.daemon.set_scan_host_progress(scan_id, 'localhost3', -1)
        self.daemon.set_scan_host_progress(scan_id, 'localhost1', 75)
        self.daemon.set_scan_host_progress(scan_id, 'localhost4', 100)
        self.daemon.set_scan_host_progress(scan_id, 'localhost2', 25)

        self.daemon.sort_host_finished(scan_id, ['localhost3', 'localhost4'])

        rounded_progress = self.daemon.scan_collection.calculate_target_progress(  # pylint: disable=line-too-long)
            scan_id
        )
        self.assertEqual(rounded_progress, 66)

    def test_set_status_interrupted(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()
        scan_id = response.findtext('id')

        end_time = self.daemon.scan_collection.get_end_time(scan_id)
        self.assertEqual(end_time, 0)

        self.daemon.interrupt_scan(scan_id)
        end_time = self.daemon.scan_collection.get_end_time(scan_id)
        self.assertNotEqual(end_time, 0)

    def test_set_status_stopped(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()
        scan_id = response.findtext('id')

        end_time = self.daemon.scan_collection.get_end_time(scan_id)
        self.assertEqual(end_time, 0)

        self.daemon.set_scan_status(scan_id, ScanStatus.STOPPED)
        end_time = self.daemon.scan_collection.get_end_time(scan_id)
        self.assertNotEqual(end_time, 0)

    def test_calculate_progress_without_current_hosts(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2, localhost3, localhost4</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

        scan_id = response.findtext('id')
        self.daemon.set_scan_host_progress(scan_id)
        self.daemon.set_scan_host_progress(scan_id, 'localhost3', -1)
        self.daemon.set_scan_host_progress(scan_id, 'localhost4', 100)

        self.daemon.sort_host_finished(scan_id, ['localhost3', 'localhost4'])

        float_progress = self.daemon.scan_collection.calculate_target_progress(
            scan_id
        )
        self.assertEqual(int(float_progress), 33)

        self.daemon.scan_collection.set_progress(scan_id, float_progress)
        progress = self.daemon.get_scan_progress(scan_id)
        self.assertEqual(progress, 33)

    def test_get_scan_host_progress(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

        scan_id = response.findtext('id')
        self.daemon.set_scan_host_progress(scan_id, 'localhost', 45)
        self.assertEqual(
            self.daemon.get_scan_host_progress(scan_id, 'localhost'), 45
        )

    def test_get_scan_without_scanid(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2, localhost3, localhost4</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        fs = FakeStream()
        self.assertRaises(
            OspdCommandError,
            self.daemon.handle_command,
            '<get_scans details="0" progress="1"/>',
            fs,
        )

    def test_set_scan_total_hosts(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2, localhost3, localhost4</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()
        scan_id = response.findtext('id')

        count = self.daemon.scan_collection.get_count_total(scan_id)
        self.assertEqual(count, 4)

        self.daemon.set_scan_total_hosts(scan_id, 3)
        count = self.daemon.scan_collection.get_count_total(scan_id)
        self.assertEqual(count, 3)

    def test_set_scan_total_hosts_zero(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2, localhost3, localhost4</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()
        scan_id = response.findtext('id')

        # Default calculated by ospd with the hosts in the target
        count = self.daemon.scan_collection.get_count_total(scan_id)
        self.assertEqual(count, 4)

        # Set to 0 (all hosts unresolved, dead, invalid target) via
        # the server. This one has priority and must be still 0 and
        # never overwritten with the calculation from host list
        self.daemon.set_scan_total_hosts(scan_id, 0)
        count = self.daemon.scan_collection.get_count_total(scan_id)
        self.assertEqual(count, 0)

    def test_set_scan_total_hosts_invalid_target(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2, localhost3, localhost4</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()
        scan_id = response.findtext('id')

        count = self.daemon.scan_collection.get_count_total(scan_id)
        self.assertEqual(count, 4)

        # The total host is set by the server as -1, because invalid target
        self.daemon.set_scan_total_hosts(scan_id, -1)
        count = self.daemon.scan_collection.get_count_total(scan_id)
        self.assertEqual(count, 0)

    def test_scan_invalid_excluded_hosts(self):

        logging.Logger.warning = Mock()
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>192.168.0.0/24</hosts>'
            '<exclude_hosts>192.168.0.1-192.168.0.200,10.0.0.0/24'
            '</exclude_hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()
        scan_id = response.findtext('id')

        # Count only the excluded hosts present in the original target.
        count = self.daemon.scan_collection.get_simplified_exclude_host_count(
            scan_id
        )
        self.assertEqual(count, 200)

        logging.Logger.warning.assert_called_with(  # pylint: disable=no-member
            "Please check the excluded host list. It contains hosts "
            "which do not belong to the target. This warning can be ignored if "
            "this was done on purpose (e.g. to exclude specific hostname)."
        )

    def test_get_scan_progress_xml(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="2">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost1, localhost2, localhost3, localhost4</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()

        response = fs.get_response()
        scan_id = response.findtext('id')

        self.daemon.set_scan_host_progress(scan_id, 'localhost3', -1)
        self.daemon.set_scan_host_progress(scan_id, 'localhost4', 100)
        self.daemon.sort_host_finished(scan_id, ['localhost3', 'localhost4'])

        self.daemon.set_scan_host_progress(scan_id, 'localhost1', 75)
        self.daemon.set_scan_host_progress(scan_id, 'localhost2', 25)

        fs = FakeStream()
        self.daemon.handle_command(
            '<get_scans scan_id="%s" details="0" progress="1"/>' % scan_id, fs
        )
        response = fs.get_response()

        progress = response.find('scan/progress')

        overall = float(progress.findtext('overall'))
        self.assertEqual(int(overall), 66)

        count_alive = progress.findtext('count_alive')
        self.assertEqual(count_alive, '1')

        count_dead = progress.findtext('count_dead')
        self.assertEqual(count_dead, '1')

        current_hosts = progress.findall('host')
        self.assertEqual(len(current_hosts), 2)

        count_excluded = progress.findtext('count_excluded')
        self.assertEqual(count_excluded, '0')

    def test_set_get_vts_version(self):
        self.daemon.set_vts_version('1234')

        version = self.daemon.get_vts_version()
        self.assertEqual('1234', version)

    def test_set_get_vts_version_error(self):
        self.assertRaises(TypeError, self.daemon.set_vts_version)

    @patch("ospd.ospd.os")
    @patch("ospd.ospd.create_process")
    def test_scan_exists(self, mock_create_process, _mock_os):
        fp = FakeStartProcess()
        mock_create_process.side_effect = fp
        mock_process = fp.call_mock
        mock_process.start.side_effect = fp.run
        mock_process.is_alive.return_value = True
        mock_process.pid = "main-scan-process"

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        response = fs.get_response()
        scan_id = response.findtext('id')
        self.assertIsNotNone(scan_id)

        status = response.get('status_text')
        self.assertEqual(status, 'OK')

        self.daemon.start_queued_scans()

        assert_called(mock_create_process)
        assert_called(mock_process.start)

        self.daemon.handle_command('<stop_scan scan_id="%s" />' % scan_id, fs)

        fs = FakeStream()
        cmd = (
            '<start_scan scan_id="' + scan_id + '">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>localhost</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>'
        )

        self.daemon.handle_command(cmd, fs)
        self.daemon.start_queued_scans()

        response = fs.get_response()
        status = response.get('status_text')
        self.assertEqual(status, 'Continue')

    def test_result_order(self):

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="1">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>a</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

        scan_id = response.findtext('id')

        self.daemon.add_scan_log(scan_id, host='a', name='a')
        self.daemon.add_scan_log(scan_id, host='c', name='c')
        self.daemon.add_scan_log(scan_id, host='b', name='b')
        hosts = ['a', 'c', 'b']

        fs = FakeStream()
        self.daemon.handle_command(
            '<get_scans scan_id="%s" details="1"/>' % scan_id, fs
        )
        response = fs.get_response()

        results = response.findall("scan/results/")

        for idx, res in enumerate(results):
            att_dict = res.attrib
            self.assertEqual(hosts[idx], att_dict['name'])

    def test_batch_result(self):
        reslist = ResultList()
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan parallel="1">'
            '<scanner_params />'
            '<targets><target>'
            '<hosts>a</hosts>'
            '<ports>22</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )
        self.daemon.start_queued_scans()
        response = fs.get_response()

        scan_id = response.findtext('id')
        reslist.add_scan_log_to_list(host='a', name='a')
        reslist.add_scan_log_to_list(host='c', name='c')
        reslist.add_scan_log_to_list(host='b', name='b')
        self.daemon.scan_collection.add_result_list(scan_id, reslist)

        hosts = ['a', 'c', 'b']

        fs = FakeStream()
        self.daemon.handle_command(
            '<get_scans scan_id="%s" details="1"/>' % scan_id, fs
        )
        response = fs.get_response()

        results = response.findall("scan/results/")

        for idx, res in enumerate(results):
            att_dict = res.attrib
            self.assertEqual(hosts[idx], att_dict['name'])

    def test_is_new_scan_allowed_false(self):
        self.daemon.scan_processes = {  # pylint: disable=protected-access
            'a': 1,
            'b': 2,
        }
        self.daemon.max_scans = 1

        self.assertFalse(self.daemon.is_new_scan_allowed())

    def test_is_new_scan_allowed_true(self):
        self.daemon.scan_processes = {  # pylint: disable=protected-access
            'a': 1,
            'b': 2,
        }
        self.daemon.max_scans = 3

        self.assertTrue(self.daemon.is_new_scan_allowed())

    def test_start_queue_scan_daemon_not_init(self):
        self.daemon.get_count_queued_scans = MagicMock(return_value=10)
        self.daemon.initialized = False
        logging.Logger.info = Mock()
        self.daemon.start_queued_scans()

        logging.Logger.info.assert_called_with(  # pylint: disable=no-member
            "Queued task can not be started because a "
            "feed update is being performed."
        )

    @patch("ospd.ospd.psutil")
    def test_free_memory_true(self, mock_psutil):
        self.daemon.min_free_mem_scan_queue = 1000
        # 1.5 GB free
        mock_psutil.virtual_memory.return_value = FakePsutil(
            available=1500000000
        )

        self.assertTrue(self.daemon.is_enough_free_memory())

    @patch("ospd.ospd.psutil")
    def test_wait_between_scan_no_scans(self, mock_psutil):
        # Enable option
        self.daemon.min_free_mem_scan_queue = 1000
        # 1.5 GB free
        mock_psutil.virtual_memory.return_value = FakePsutil(
            available=1500000000
        )
        # Not enough time between scans, but no running scan
        self.daemon.last_scan_start_time = time.time() - 20

        self.assertTrue(self.daemon.is_enough_free_memory())

    @patch("ospd.ospd.psutil")
    def test_wait_between_scan_run_scans_not_allow(self, mock_psutil):
        # Enable option
        self.daemon.min_free_mem_scan_queue = 1000
        # 1.5 GB free
        mock_psutil.virtual_memory.return_value = FakePsutil(
            available=1500000000
        )

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets><target>'
            '<hosts>localhosts,192.168.0.0/24</hosts>'
            '<ports>80,443</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )

        # There is a running scan
        self.daemon.start_queued_scans()

        # Not enough time between scans
        self.daemon.last_scan_start_time = time.time() - 20

        self.assertFalse(self.daemon.is_enough_free_memory())

    @patch("ospd.ospd.psutil")
    def test_wait_between_scan_allow(self, mock_psutil):
        # Enable option
        self.daemon.min_free_mem_scan_queue = 1000
        # 1.5 GB free
        mock_psutil.virtual_memory.return_value = FakePsutil(
            available=1500000000
        )

        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets><target>'
            '<hosts>localhosts,192.168.0.0/24</hosts>'
            '<ports>80,443</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )

        # There is a running scan, enough memory and enough time
        # in between
        self.daemon.start_queued_scans()

        self.daemon.last_scan_start_time = time.time() - 65

        self.assertTrue(self.daemon.is_enough_free_memory())

    @patch("ospd.ospd.psutil")
    def test_free_memory_false(self, mock_psutil):
        self.daemon.min_free_mem_scan_queue = 2000
        # 1.5 GB free
        mock_psutil.virtual_memory.return_value = FakePsutil(
            available=1500000000
        )

        self.assertFalse(self.daemon.is_enough_free_memory())

    def test_count_queued_scans(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets><target>'
            '<hosts>localhosts,192.168.0.0/24</hosts>'
            '<ports>80,443</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )

        self.assertEqual(self.daemon.get_count_queued_scans(), 1)
        self.daemon.start_queued_scans()
        self.assertEqual(self.daemon.get_count_queued_scans(), 0)

    def test_count_running_scans(self):
        fs = FakeStream()
        self.daemon.handle_command(
            '<start_scan>'
            '<scanner_params /><vts><vt id="1.2.3.4" />'
            '</vts>'
            '<targets><target>'
            '<hosts>localhosts,192.168.0.0/24</hosts>'
            '<ports>80,443</ports>'
            '</target></targets>'
            '</start_scan>',
            fs,
        )

        self.assertEqual(self.daemon.get_count_running_scans(), 0)
        self.daemon.start_queued_scans()
        self.assertEqual(self.daemon.get_count_running_scans(), 1)

    def test_ids_iterator_dict_modified(self):
        self.daemon.scan_collection.scans_table = {'a': 1, 'b': 2}

        for _ in self.daemon.scan_collection.ids_iterator():
            self.daemon.scan_collection.scans_table['c'] = 3

        self.assertEqual(len(self.daemon.scan_collection.scans_table), 3)
