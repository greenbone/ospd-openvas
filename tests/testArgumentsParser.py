# Copyright (C) 2014-2018 Greenbone Networks GmbH
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

""" Test module for command line arguments.
"""

import logging
import unittest

from ospd import misc
from ospd.misc import create_args_parser, get_common_args


class testArgumentParser(unittest.TestCase):

    def setUp(self):
        self.parser = create_args_parser('Wrapper name')

    def testPortiInterval(self):
        self.assertRaises(SystemExit, get_common_args, self.parser, '--port=65536'.split())
        self.assertRaises(SystemExit, get_common_args, self.parser, '--port=0'.split())
        args = get_common_args(self.parser, '--port=3353'.split())
        self.assertEqual(3353, args['port'])

    def testPortasString(self):
        self.assertRaises(SystemExit, get_common_args, self.parser, '--port=abcd'.split())

    def testDefaultPort(self):
        args = get_common_args(self.parser, [])
        self.assertEqual(misc.PORT, args['port'])

    def testDefaultAddress(self):
        args = get_common_args(self.parser, [])
        self.assertEqual(misc.ADDRESS, args['address'])
        
    def testAddressParam(self):
        args = get_common_args(self.parser, '-b 1.2.3.4'.split())
        self.assertEqual('1.2.3.4', args['address'])

    def testDefaultLogLevel(self):
        args = get_common_args(self.parser, [])
        self.assertEqual(logging.WARNING, args['log_level'])
        
    def testCorrectDCLogLevel(self):
        args = get_common_args(self.parser, '-L error'.split())
        self.assertEqual(logging.ERROR, args['log_level'])

    def testCorrectUCLogLevel(self):
        args = get_common_args(self.parser, '-L INFO'.split())
        self.assertEqual(logging.INFO, args['log_level'])

    def testinCorrectLogLevel(self):
        self.assertRaises(SystemExit, get_common_args, self.parser,'-L blah'.split())

    def testNonExistingKey(self):
        self.assertRaises(SystemExit, get_common_args, self.parser, '-k abcdef.ghijkl'.split())

    def testExistingKey(self):
        args = get_common_args(self.parser, '-k /etc/passwd'.split())
        self.assertEqual('/etc/passwd', args['keyfile'])

    def testDefaultKey(self):
        args = get_common_args(self.parser, [])
        self.assertEqual(misc.KEY_FILE, args['keyfile'])
