# Copyright (C) 2014-2021 Greenbone AG
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

""" Test module for command line arguments.
"""

import unittest

from unittest.mock import patch

from io import StringIO
from pathlib import Path
from typing import List

from ospd.parser import (
    DEFAULT_MQTT_BROKER_ADDRESS,
    DEFAULT_MQTT_BROKER_PORT,
    Arguments,
    DEFAULT_ADDRESS,
    DEFAULT_PORT,
    DEFAULT_KEY_FILE,
    DEFAULT_NICENESS,
    DEFAULT_SCANINFO_STORE_TIME,
    DEFAULT_UNIX_SOCKET_PATH,
    DEFAULT_PID_PATH,
    DEFAULT_LOCKFILE_DIR_PATH,
)
from ospd_openvas.notus import NotusParser

here = Path(__file__).absolute().parent


class ArgumentParserTestCase(unittest.TestCase):
    def setUp(self):
        self.parser = NotusParser()

    def parse_args(self, args: List[str]) -> Arguments:
        return self.parser.parse_arguments(args)

    @patch('sys.stderr', new_callable=StringIO)
    def test_port_interval(self, _mock_stderr):
        with self.assertRaises(SystemExit):
            self.parse_args(['--port=65536'])

        with self.assertRaises(SystemExit):
            self.parse_args(['--port=0'])

        args = self.parse_args(['--port=3353'])
        self.assertEqual(3353, args.port)

    @patch('sys.stderr', new_callable=StringIO)
    def test_port_as_string(self, _mock_stderr):
        with self.assertRaises(SystemExit):
            self.parse_args(['--port=abcd'])

    def test_address_param(self):
        args = self.parse_args('-b 1.2.3.4'.split())
        self.assertEqual('1.2.3.4', args.address)

    def test_correct_lower_case_log_level(self):
        args = self.parse_args('-L error'.split())
        self.assertEqual('ERROR', args.log_level)

    def test_correct_upper_case_log_level(self):
        args = self.parse_args('-L INFO'.split())
        self.assertEqual('INFO', args.log_level)

    @patch('sys.stderr', new_callable=StringIO)
    def test_correct_log_level(self, _mock_stderr):
        with self.assertRaises(SystemExit):
            self.parse_args('-L blah'.split())

    def test_non_existing_key(self):
        args = self.parse_args('-k foo'.split())
        self.assertEqual('foo', args.key_file)

    def test_existing_key(self):
        args = self.parse_args('-k /etc/passwd'.split())
        self.assertEqual('/etc/passwd', args.key_file)

    def test_disable_notus_hashsum_verification(self):
        args = self.parse_args(
            '--disable-notus-hashsum-verification true'.split()
        )
        self.assertEqual(args.disable_notus_hashsum_verification, True)

    def test_defaults(self):
        args = self.parse_args([])

        self.assertIsNone(args.config)
        self.assertEqual(args.key_file, DEFAULT_KEY_FILE)
        self.assertEqual(args.niceness, DEFAULT_NICENESS)
        self.assertEqual(args.log_level, 'INFO')
        self.assertEqual(args.address, DEFAULT_ADDRESS)
        self.assertEqual(args.port, DEFAULT_PORT)
        self.assertEqual(args.scaninfo_store_time, DEFAULT_SCANINFO_STORE_TIME)
        self.assertEqual(args.unix_socket, DEFAULT_UNIX_SOCKET_PATH)
        self.assertEqual(args.pid_file, DEFAULT_PID_PATH)
        self.assertEqual(args.lock_file_dir, DEFAULT_LOCKFILE_DIR_PATH)
        self.assertEqual(args.mqtt_broker_address, DEFAULT_MQTT_BROKER_ADDRESS)
        self.assertEqual(args.mqtt_broker_port, DEFAULT_MQTT_BROKER_PORT)
        self.assertEqual(args.disable_notus_hashsum_verification, False)


class ArgumentParserConfigTestCase(unittest.TestCase):
    def setUp(self):
        self.parser = NotusParser()

    def parse_args(self, args: List[str]) -> Arguments:
        return self.parser.parse_arguments(args)

    def test_using_config(self):
        config_file = str(here / 'testing.conf')
        args = self.parse_args(['--config', config_file])

        self.assertEqual(args.key_file, '/foo/key.pem')
        self.assertEqual(args.niceness, 666)
        self.assertEqual(args.log_level, 'DEBUG')
        self.assertEqual(args.address, '6.6.6.6')
        self.assertEqual(args.port, 6666)
        self.assertEqual(args.scaninfo_store_time, 123)
        self.assertEqual(args.config, config_file)
        self.assertEqual(args.unix_socket, '/foo/ospd-openvas.sock')
        self.assertEqual(args.pid_file, '/foo/ospd-openvas.pid')
        self.assertEqual(args.lock_file_dir, '/foo/openvas')
        self.assertEqual(args.mqtt_broker_address, 'foo.bar.com')
        self.assertEqual(args.mqtt_broker_port, 1234)
        self.assertEqual(args.notus_feed_dir, '/foo/advisories')

    @patch('sys.stderr', new_callable=StringIO)
    def test_not_existing_config(self, _mock):
        with self.assertRaises(SystemExit):
            self.parse_args(['--config', 'foo.conf'])
