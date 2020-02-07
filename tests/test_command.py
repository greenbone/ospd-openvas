# Copyright (C) 2020 Greenbone Networks GmbH
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

from unittest import TestCase
from unittest.mock import patch

from xml.etree import ElementTree as et

from ospd.command.command import GetPerformance, StartScan, StopScan
from ospd.errors import OspdCommandError

from .helper import DummyWrapper, assert_called


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
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params /><vt_selection />'
            '</start_scan>'
        )

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

    @patch("ospd.command.command.create_process")
    def test_scan_with_vts(self, mock_create_process):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        request = et.fromstring(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_single id="1.2.3.4" />'
            '</vt_selection>'
            '</start_scan>'
        )

        # With one vt, without params
        response = et.fromstring(cmd.handle_xml(request))
        scan_id = response.findtext('id')

        self.assertEqual(
            daemon.get_scan_vts(scan_id), {'1.2.3.4': {}, 'vt_groups': []}
        )
        self.assertNotEqual(daemon.get_scan_vts(scan_id), {'1.2.3.6': {}})

        assert_called(mock_create_process)

    @patch("ospd.command.command.create_process")
    def test_scan_without_vts(self, mock_create_process):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # With out vtS
        request = et.fromstring(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params />'
            '</start_scan>'
        )
        response = et.fromstring(cmd.handle_xml(request))

        scan_id = response.findtext('id')

        self.assertEqual(daemon.get_scan_vts(scan_id), {})

        assert_called(mock_create_process)

    def test_scan_with_vts_and_param_missing_vt_param_id(self):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # Raise because no vt_param id attribute
        request = et.fromstring(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_single id="1234"><vt_value>200</vt_value></vt_single>'
            '</vt_selection>'
            '</start_scan>'
        )

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

    @patch("ospd.command.command.create_process")
    def test_scan_with_vts_and_param(self, mock_create_process):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # No error
        request = et.fromstring(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_single id="1234">'
            '<vt_value id="ABC">200</vt_value>'
            '</vt_single>'
            '</vt_selection>'
            '</start_scan>'
        )
        response = et.fromstring(cmd.handle_xml(request))
        scan_id = response.findtext('id')

        self.assertEqual(
            daemon.get_scan_vts(scan_id),
            {'1234': {'ABC': '200'}, 'vt_groups': []},
        )

        assert_called(mock_create_process)

    def test_scan_with_vts_and_param_missing_vt_group_filter(self):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # Raise because no vtgroup filter attribute
        request = et.fromstring(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params />'
            '<vt_selection><vt_group/></vt_selection>'
            '</start_scan>'
        )

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

    @patch("ospd.command.command.create_process")
    def test_scan_with_vts_and_param_with_vt_group_filter(
        self, mock_create_process
    ):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)

        # No error
        request = et.fromstring(
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params />'
            '<vt_selection>'
            '<vt_group filter="a"/>'
            '</vt_selection>'
            '</start_scan>'
        )
        response = et.fromstring(cmd.handle_xml(request))
        scan_id = response.findtext('id')

        self.assertEqual(daemon.get_scan_vts(scan_id), {'vt_groups': ['a']})

        assert_called(mock_create_process)

    def test_scan_multi_target_parallel_with_error(self):
        daemon = DummyWrapper([])
        cmd = StartScan(daemon)
        request = et.fromstring(
            '<start_scan parallel="100a">'
            '<scanner_params />'
            '<targets>'
            '<target>'
            '<hosts>localhosts</hosts>'
            '<ports>22</ports>'
            '</target>'
            '</targets>'
            '</start_scan>'
        )

        with self.assertRaises(OspdCommandError):
            cmd.handle_xml(request)

    @patch("ospd.ospd.OSPDaemon")
    @patch("ospd.command.command.create_process")
    def test_scan_multi_target_parallel_100(
        self, mock_create_process, mock_daemon
    ):
        daemon = mock_daemon()
        daemon.create_scan.return_value = '1'
        cmd = StartScan(daemon)
        request = et.fromstring(
            '<start_scan parallel="100">'
            '<scanner_params />'
            '<targets>'
            '<target>'
            '<hosts>localhosts</hosts>'
            '<ports>22</ports>'
            '</target>'
            '</targets>'
            '</start_scan>'
        )
        response = et.fromstring(cmd.handle_xml(request))

        self.assertEqual(response.get('status'), '200')

        assert_called(mock_create_process)


class StopCommandTestCase(TestCase):
    @patch("ospd.ospd.os")
    @patch("ospd.command.command.create_process")
    def test_stop_scan(self, mock_create_process, mock_os):
        mock_process = mock_create_process.return_value
        mock_process.is_alive.return_value = True
        mock_process.pid = "foo"

        daemon = DummyWrapper([])
        request = (
            '<start_scan target="localhost" ports="80, 443">'
            '<scanner_params />'
            '</start_scan>'
        )
        response = et.fromstring(daemon.handle_command(request))

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
