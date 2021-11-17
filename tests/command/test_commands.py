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

from unittest import TestCase
from unittest.mock import patch

from xml.etree import ElementTree as et

from ospd.command.command import (
    GetPerformance,
    StartScan,
    StopScan,
    GetMemoryUsage,
)
from ospd.errors import OspdCommandError, OspdError
from ospd.misc import create_process

from ..helper import DummyWrapper, assert_called, FakeStream, FakeDataManager


class GetPerformanceTestCase(TestCase):
    @patch('ospd.command.command.subprocess')
    def test_get_performance(self, mock_subproc):
        cmd = GetPerformance(None)
        mock_subproc.check_output.return_value = b'foo'
        response = et.fromstring(
            cmd.handle_xml(
                et.fromstring(
                    '<get_performance start="0" end="0" titles="mem"/>'
                )
            )
        )

        self.assertEqual(response.get('status'), '200')
        self.assertEqual(response.tag, 'get_performance_response')

    def test_get_performance_fail_int(self):
        cmd = GetPerformance(None)
        request = et.fromstring(
            '<get_performance start="a" end="0" titles="mem"/>'
        )

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

    def test_get_performance_fail_regex(self):
        cmd = GetPerformance(None)
        request = et.fromstring(
            '<get_performance start="0" end="0" titles="mem|bar"/>'
        )

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

    def test_get_performance_fail_cmd(self):
        cmd = GetPerformance(None)
        request = et.fromstring(
            '<get_performance start="0" end="0" titles="mem1"/>'
        )

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)


class StartScanTestCase(TestCase):
    def test_scan_with_vts_empty_vt_list(self):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)
        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params /><vt_selection />'
            '</start_scan>'
        )

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

    @patch("ospd.ospd.create_process")
    def test_scan_with_vts(self, mock_create_process):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_single id="1.2.3.4" />'
            '</vt_selection>'
            '</start_scan>'
        )

        # With one vt, without params
        response = et.fromstring(cmd.handle_xml(request))
        daemon.start_queued_scans()
        scan_id = response.findtext('id')

        vts_collection = daemon.get_scan_vts(scan_id)
        self.assertEqual(vts_collection, {'1.2.3.4': {}, 'vt_groups': []})
        self.assertNotEqual(vts_collection, {'1.2.3.6': {}})

        daemon.start_queued_scans()
        assert_called(mock_create_process)

    def test_scan_pop_vts(self):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_single id="1.2.3.4" />'
            '</vt_selection>'
            '</start_scan>'
        )

        # With one vt, without params
        response = et.fromstring(cmd.handle_xml(request))
        scan_id = response.findtext('id')
        daemon.start_queued_scans()
        vts_collection = daemon.get_scan_vts(scan_id)
        self.assertEqual(vts_collection, {'1.2.3.4': {}, 'vt_groups': []})
        self.assertRaises(KeyError, daemon.get_scan_vts, scan_id)

    def test_scan_pop_ports(self):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_single id="1.2.3.4" />'
            '</vt_selection>'
            '</start_scan>'
        )

        # With one vt, without params
        response = et.fromstring(cmd.handle_xml(request))
        daemon.start_queued_scans()
        scan_id = response.findtext('id')

        ports = daemon.scan_collection.get_ports(scan_id)
        self.assertEqual(ports, '80, 443')
        self.assertRaises(KeyError, daemon.scan_collection.get_ports, scan_id)

    @patch("ospd.ospd.create_process")
    def test_scan_without_vts(self, mock_create_process):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # With out vts
        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '</start_scan>'
        )

        response = et.fromstring(cmd.handle_xml(request))
        daemon.start_queued_scans()

        scan_id = response.findtext('id')
        self.assertEqual(daemon.get_scan_vts(scan_id), {})

        assert_called(mock_create_process)

    def test_scan_with_vts_and_param_missing_vt_param_id(self):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # Raise because no vt_param id attribute
        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_single id="1234"><vt_value>200</vt_value></vt_single>'
            '</vt_selection>'
            '</start_scan>'
        )

        with self.assertRaises(OspdError):
            cmd.handle_xml(request)

    @patch("ospd.ospd.create_process")
    def test_scan_with_vts_and_param(self, mock_create_process):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # No error
        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_single id="1234">'
            '<vt_value id="ABC">200</vt_value>'
            '</vt_single>'
            '</vt_selection>'
            '</start_scan>'
        )
        response = et.fromstring(cmd.handle_xml(request))
        daemon.start_queued_scans()

        scan_id = response.findtext('id')

        self.assertEqual(
            daemon.get_scan_vts(scan_id),
            {'1234': {'ABC': '200'}, 'vt_groups': []},
        )
        daemon.start_queued_scans()
        assert_called(mock_create_process)

    def test_scan_with_vts_and_param_missing_vt_group_filter(self):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # Raise because no vtgroup filter attribute
        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '<vt_selection><vt_group/></vt_selection>'
            '</start_scan>'
        )
        daemon.start_queued_scans()

        with self.assertRaises(OspdError):
            cmd.handle_xml(request)

    @patch("ospd.ospd.create_process")
    def test_scan_with_vts_and_param_with_vt_group_filter(
        self, mock_create_process
    ):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # No error
        request = et.fromstring(
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhost</hosts>'
            '<ports>80, 443</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_group filter="a"/>'
            '</vt_selection>'
            '</start_scan>'
        )
        response = et.fromstring(cmd.handle_xml(request))
        daemon.start_queued_scans()
        scan_id = response.findtext('id')

        self.assertEqual(daemon.get_scan_vts(scan_id), {'vt_groups': ['a']})

        assert_called(mock_create_process)

    @patch("ospd.ospd.create_process")
    @patch("ospd.command.command.logger")
    def test_scan_ignore_multi_target(self, mock_logger, mock_create_process):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)
        request = et.fromstring(
            '<start_scan parallel="100a">'
            '<targets>'
            '<target>'
            '<hosts>localhosts</hosts>'
            '<ports>22</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '</start_scan>'
        )

        cmd.handle_xml(request)
        daemon.start_queued_scans()
        assert_called(mock_logger.warning)
        assert_called(mock_create_process)

    def test_max_queued_scans_reached(self):
        daemon = DummyWrapper([])
        daemon.max_queued_scans = 1
        cmd = StartScan(daemon)
        request = et.fromstring(
            '<start_scan parallel="100a">'
            '<targets>'
            '<target>'
            '<hosts>localhosts</hosts>'
            '<ports>22</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '</start_scan>'
        )

        # create first scan
        response = et.fromstring(cmd.handle_xml(request))
        scan_id_1 = response.findtext('id')

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

        daemon.scan_collection.remove_file_pickled_scan_info(scan_id_1)

    @patch("ospd.ospd.create_process")
    @patch("ospd.command.command.logger")
    def test_scan_use_legacy_target_and_port(
        self, mock_logger, mock_create_process
    ):
        daemon = DummyWrapper([])
        daemon.scan_collection.datamanager = FakeDataManager()

        cmd = StartScan(daemon)
        request = et.fromstring(
            '<start_scan target="localhost" ports="22">'
            '<scanner_params />'
            '</start_scan>'
        )

        response = et.fromstring(cmd.handle_xml(request))
        daemon.start_queued_scans()
        scan_id = response.findtext('id')

        self.assertIsNotNone(scan_id)

        self.assertEqual(daemon.get_scan_host(scan_id), 'localhost')
        self.assertEqual(daemon.get_scan_ports(scan_id), '22')

        assert_called(mock_logger.warning)
        assert_called(mock_create_process)


class StopCommandTestCase(TestCase):
    @patch("ospd.ospd.os")
    @patch("ospd.ospd.create_process")
    def test_stop_scan(self, mock_create_process, mock_os):
        mock_process = mock_create_process.return_value
        mock_process.is_alive.return_value = True
        mock_process.pid = "foo"
        fs = FakeStream()
        daemon = DummyWrapper([])
        daemon.scan_collection.datamanager = FakeDataManager()
        request = (
            '<start_scan>'
            '<targets>'
            '<target>'
            '<hosts>localhosts</hosts>'
            '<ports>22</ports>'
            '</target>'
            '</targets>'
            '<scanner_params />'
            '</start_scan>'
        )
        daemon.handle_command(request, fs)
        response = fs.get_response()

        daemon.start_queued_scans()

        assert_called(mock_create_process)
        assert_called(mock_process.start)

        scan_id = response.findtext('id')

        request = et.fromstring('<stop_scan scan_id="%s" />' % scan_id)
        cmd = StopScan(daemon)
        cmd.handle_xml(request)

        assert_called(mock_process.terminate)

        mock_os.getpgid.assert_called_with('foo')

    def test_unknown_scan_id(self):
        daemon = DummyWrapper([])
        cmd = StopScan(daemon)
        request = et.fromstring('<stop_scan scan_id="foo" />')

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

    def test_missing_scan_id(self):
        request = et.fromstring('<stop_scan />')
        cmd = StopScan(None)

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)


class GetMemoryUsageTestCase(TestCase):
    def test_with_main_process_only(self):
        cmd = GetMemoryUsage(None)

        request = et.fromstring('<get_memory_usage />')

        response = et.fromstring(cmd.handle_xml(request))
        processes_element = response.find('processes')

        process_elements = processes_element.findall('process')

        self.assertTrue(len(process_elements), 1)

        main_process_element = process_elements[0]

        rss_element = main_process_element.find('rss')
        vms_element = main_process_element.find('vms')
        shared_element = main_process_element.find('shared')

        self.assertIsNotNone(rss_element)
        self.assertIsNotNone(rss_element.text)

        self.assertIsNotNone(vms_element)
        self.assertIsNotNone(vms_element.text)

        self.assertIsNotNone(shared_element)
        self.assertIsNotNone(shared_element.text)

    def test_with_subprocess(self):
        cmd = GetMemoryUsage(None)

        def foo():  # pylint: disable=blacklisted-name
            time.sleep(60)

        create_process(foo, args=[])

        request = et.fromstring('<get_memory_usage />')

        response = et.fromstring(cmd.handle_xml(request))
        processes_element = response.find('processes')

        process_elements = processes_element.findall('process')

        self.assertTrue(len(process_elements), 2)

        for process_element in process_elements:
            rss_element = process_element.find('rss')
            vms_element = process_element.find('vms')
            shared_element = process_element.find('shared')

            self.assertIsNotNone(rss_element)
            self.assertIsNotNone(rss_element.text)

            self.assertIsNotNone(vms_element)
            self.assertIsNotNone(vms_element.text)

            self.assertIsNotNone(shared_element)
            self.assertIsNotNone(shared_element.text)

    def test_with_subsubprocess(self):
        cmd = GetMemoryUsage(None)

        def bar():  # pylint: disable=blacklisted-name
            create_process(foo, args=[])

        def foo():  # pylint: disable=blacklisted-name
            time.sleep(60)

        create_process(bar, args=[])

        request = et.fromstring('<get_memory_usage />')

        response = et.fromstring(cmd.handle_xml(request))
        processes_element = response.find('processes')

        process_elements = processes_element.findall('process')

        # sub-sub-processes aren't listed
        self.assertTrue(len(process_elements), 2)

        for process_element in process_elements:
            rss_element = process_element.find('rss')
            vms_element = process_element.find('vms')
            shared_element = process_element.find('shared')

            self.assertIsNotNone(rss_element)
            self.assertIsNotNone(rss_element.text)

            self.assertIsNotNone(vms_element)
            self.assertIsNotNone(vms_element.text)

            self.assertIsNotNone(shared_element)
            self.assertIsNotNone(shared_element.text)
