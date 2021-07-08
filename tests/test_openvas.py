# -*- coding: utf-8 -*-
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


import subprocess

from unittest import TestCase
from unittest.mock import patch, MagicMock

import psutil

from ospd_openvas.openvas import Openvas


class OpenvasCommandTestCase(TestCase):
    @patch('ospd_openvas.openvas.subprocess.check_output')
    def test_get_version(self, mock_check_output: MagicMock):
        mock_check_output.return_value = b"OpenVAS 20.08"

        self.assertEqual(Openvas.get_version(), 'OpenVAS 20.08')

        mock_check_output.assert_called_with(
            ['openvas', '-V'], stderr=subprocess.STDOUT
        )

    @patch('ospd_openvas.openvas.subprocess.check_output')
    def test_get_version_not_found(self, mock_check_output: MagicMock):
        mock_check_output.return_value = b"Foo 20.08"

        self.assertIsNone(Openvas.get_version())

        mock_check_output.assert_called_with(
            ['openvas', '-V'], stderr=subprocess.STDOUT
        )

    @patch('ospd_openvas.openvas.subprocess.check_output')
    def test_get_version_with_error(self, mock_check_output: MagicMock):
        mock_check_output.side_effect = subprocess.SubprocessError('foo')

        self.assertIsNone(Openvas.get_version())

        mock_check_output.assert_called_with(
            ['openvas', '-V'], stderr=subprocess.STDOUT
        )

        mock_check_output.reset_mock()
        mock_check_output.side_effect = OSError('foo')

        self.assertIsNone(Openvas.get_version())

        mock_check_output.assert_called_with(
            ['openvas', '-V'], stderr=subprocess.STDOUT
        )

    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_check(self, mock_check_call: MagicMock):
        self.assertTrue(Openvas.check())
        mock_check_call.assert_called_with(
            ['openvas', '-V'], stdout=subprocess.DEVNULL
        )

    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_check_with_error(self, mock_check_call: MagicMock):
        mock_check_call.side_effect = subprocess.SubprocessError('foo')

        self.assertFalse(Openvas.check())
        mock_check_call.assert_called_with(
            ['openvas', '-V'], stdout=subprocess.DEVNULL
        )

        mock_check_call.reset_mock()
        mock_check_call.side_effect = OSError('foo')

        self.assertFalse(Openvas.check())
        mock_check_call.assert_called_with(
            ['openvas', '-V'], stdout=subprocess.DEVNULL
        )

    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_check_sudo(self, mock_check_call: MagicMock):
        self.assertTrue(Openvas.check_sudo())
        mock_check_call.assert_called_with(
            ['sudo', '-n', 'openvas', '-s'], stdout=subprocess.DEVNULL
        )

    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_check_sudo_with_error(self, mock_check_call: MagicMock):
        mock_check_call.side_effect = subprocess.SubprocessError('foo')

        self.assertFalse(Openvas.check_sudo())
        mock_check_call.assert_called_with(
            ['sudo', '-n', 'openvas', '-s'], stdout=subprocess.DEVNULL
        )

        mock_check_call.reset_mock()
        mock_check_call.side_effect = OSError('foo')

        self.assertFalse(Openvas.check_sudo())
        mock_check_call.assert_called_with(
            ['sudo', '-n', 'openvas', '-s'], stdout=subprocess.DEVNULL
        )

    @patch('ospd_openvas.openvas.logger')
    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_load_vts_into_redis(self, mock_check_call, mock_logger):
        Openvas.load_vts_into_redis()

        mock_check_call.assert_called_with(
            ['openvas', '--update-vt-info'], stdout=subprocess.DEVNULL
        )

        mock_logger.error.assert_not_called()

    @patch('ospd_openvas.openvas.logger')
    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_load_vts_into_redis_with_error(
        self, mock_check_call: MagicMock, mock_logger: MagicMock
    ):
        mock_check_call.side_effect = subprocess.SubprocessError('foo')

        Openvas.load_vts_into_redis()

        mock_check_call.assert_called_with(
            ['openvas', '--update-vt-info'], stdout=subprocess.DEVNULL
        )

        self.assertEqual(mock_logger.error.call_count, 1)

    @patch('ospd_openvas.openvas.logger')
    @patch('ospd_openvas.openvas.subprocess.check_output')
    def test_get_settings(
        self, mock_check_output: MagicMock, _mock_logger: MagicMock
    ):
        mock_check_output.return_value = (
            b'non_simult_ports = 22 \n plugins_folder = /foo/bar\nfoo = yes\n'
            b'bar=no\nipsum= \nlorem\n'
        )

        settings = Openvas.get_settings()

        mock_check_output.assert_called_with(['openvas', '-s'])

        self.assertEqual(settings['non_simult_ports'], '22')
        self.assertEqual(settings['plugins_folder'], '/foo/bar')
        self.assertEqual(settings['foo'], 1)
        self.assertEqual(settings['bar'], 0)
        self.assertFalse('ipsum' in settings)
        self.assertFalse('lorem' in settings)

    @patch('ospd_openvas.openvas.logger')
    @patch('ospd_openvas.openvas.subprocess.check_output')
    def test_get_settings_with_error(
        self, mock_check_output: MagicMock, _mock_logger: MagicMock
    ):
        mock_check_output.side_effect = subprocess.SubprocessError('foo')

        settings = Openvas.get_settings()

        mock_check_output.assert_called_with(['openvas', '-s'])

        self.assertFalse(settings)  # settings dict is empty

        mock_check_output.reset_mock()

        mock_check_output.side_effect = OSError('foo')

        settings = Openvas.get_settings()

        mock_check_output.assert_called_with(['openvas', '-s'])

        self.assertFalse(settings)  # settings dict is empty

        mock_check_output.reset_mock()

        # https://gehrcke.de/2015/12/how-to-raise-unicodedecodeerror-in-python-3/
        mock_check_output.side_effect = UnicodeDecodeError(
            'funnycodec', b'\x00\x00', 1, 2, 'This is just a fake reason!'
        )

        settings = Openvas.get_settings()

        mock_check_output.assert_called_with(['openvas', '-s'])

        self.assertFalse(settings)  # settings dict is empty

    @patch('ospd_openvas.openvas.psutil.Popen')
    def test_start_scan(self, mock_popen: MagicMock):
        proc = Openvas.start_scan('scan_1')

        mock_popen.assert_called_with(
            ['openvas', '--scan-start', 'scan_1'], shell=False
        )

        self.assertIsNotNone(proc)

    @patch('ospd_openvas.openvas.psutil.Popen')
    def test_start_scan_with_sudo(self, mock_popen: MagicMock):
        proc = Openvas.start_scan('scan_1', sudo=True)

        mock_popen.assert_called_with(
            ['sudo', '-n', 'openvas', '--scan-start', 'scan_1'], shell=False
        )

        self.assertIsNotNone(proc)

    @patch('ospd_openvas.openvas.psutil.Popen')
    def test_start_scan_with_niceness(self, mock_popen: MagicMock):
        proc = Openvas.start_scan('scan_1', niceness=4)

        mock_popen.assert_called_with(
            ['nice', '-n', 4, 'openvas', '--scan-start', 'scan_1'], shell=False
        )

        self.assertIsNotNone(proc)

    @patch('ospd_openvas.openvas.psutil.Popen')
    def test_start_scan_with_niceness_and_sudo(self, mock_popen: MagicMock):
        proc = Openvas.start_scan('scan_1', niceness=4, sudo=True)

        mock_popen.assert_called_with(
            [
                'nice',
                '-n',
                4,
                'sudo',
                '-n',
                'openvas',
                '--scan-start',
                'scan_1',
            ],
            shell=False,
        )

        self.assertIsNotNone(proc)

    @patch('ospd_openvas.openvas.logger')
    @patch('ospd_openvas.openvas.psutil.Popen')
    def test_start_scan_error(
        self, mock_popen: MagicMock, mock_logger: MagicMock
    ):
        mock_popen.side_effect = psutil.Error('foo')

        proc = Openvas.start_scan('scan_1')

        mock_popen.assert_called_with(
            ['openvas', '--scan-start', 'scan_1'], shell=False
        )

        self.assertIsNone(proc)

        self.assertEqual(mock_logger.warning.call_count, 1)

        mock_popen.reset_mock()
        mock_logger.reset_mock()

        mock_popen.side_effect = OSError('foo')

        proc = Openvas.start_scan('scan_1')

        mock_popen.assert_called_with(
            ['openvas', '--scan-start', 'scan_1'], shell=False
        )

        self.assertIsNone(proc)

        self.assertEqual(mock_logger.warning.call_count, 1)

    @patch('ospd_openvas.openvas.logger')
    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_stop_scan(
        self, mock_check_call: MagicMock, _mock_logger: MagicMock
    ):
        success = Openvas.stop_scan('scan_1')

        mock_check_call.assert_called_with(['openvas', '--scan-stop', 'scan_1'])

        self.assertTrue(success)

    @patch('ospd_openvas.openvas.logger')
    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_stop_scan_with_sudo(
        self, mock_check_call: MagicMock, _mock_logger: MagicMock
    ):
        success = Openvas.stop_scan('scan_1', sudo=True)

        mock_check_call.assert_called_with(
            ['sudo', '-n', 'openvas', '--scan-stop', 'scan_1']
        )

        self.assertTrue(success)

    @patch('ospd_openvas.openvas.logger')
    @patch('ospd_openvas.openvas.subprocess.check_call')
    def test_stop_scan_with_error(
        self, mock_check_call: MagicMock, mock_logger: MagicMock
    ):
        mock_check_call.side_effect = subprocess.SubprocessError('foo')

        success = Openvas.stop_scan('scan_1')

        mock_check_call.assert_called_with(['openvas', '--scan-stop', 'scan_1'])

        self.assertFalse(success)

        self.assertEqual(mock_logger.warning.call_count, 1)

        mock_check_call.reset_mock()
        mock_logger.reset_mock()

        mock_check_call.side_effect = OSError('foo')

        success = Openvas.stop_scan('scan_1')

        mock_check_call.assert_called_with(['openvas', '--scan-stop', 'scan_1'])

        self.assertFalse(success)

        self.assertEqual(mock_logger.warning.call_count, 1)
