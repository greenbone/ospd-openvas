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

""" Test module for command line arguments.
"""

import unittest

from unittest.mock import patch

from io import StringIO
from typing import List

from ospd.parser import (
    create_parser,
    Arguments,
    DEFAULT_ADDRESS,
    DEFAULT_PORT,
    DEFAULT_KEY_FILE,
    DEFAULT_NICENESS,
    DEFAULT_SCANINFO_STORE_TIME,
    DEFAULT_CONFIG_PATH,
    DEFAULT_UNIX_SOCKET_PATH,
    DEFAULT_PID_PATH,
    DEFAULT_LOCKFILE_DIR_PATH,
)


class ArgumentParserTestCase(unittest.TestCase):
    def setUp(self):
        self.parser = create_parser('Wrapper name')

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

    def test_defaults(self):
        args = self.parse_args([])

        self.assertEqual(args.key_file, DEFAULT_KEY_FILE)
        self.assertEqual(args.niceness, DEFAULT_NICENESS)
        self.assertEqual(args.log_level, 'INFO')
        self.assertEqual(args.address, DEFAULT_ADDRESS)
        self.assertEqual(args.port, DEFAULT_PORT)
        self.assertEqual(args.scaninfo_store_time, DEFAULT_SCANINFO_STORE_TIME)
        self.assertEqual(args.config, DEFAULT_CONFIG_PATH)
        self.assertEqual(args.unix_socket, DEFAULT_UNIX_SOCKET_PATH)
        self.assertEqual(args.pid_file, DEFAULT_PID_PATH)
        self.assertEqual(args.lock_file_dir, DEFAULT_LOCKFILE_DIR_PATH)
