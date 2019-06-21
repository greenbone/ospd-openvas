# Copyright (C) 2018 Greenbone Networks GmbH
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

""" Test suites for Port manipulation.
"""

from __future__ import print_function

import unittest

from ospd.misc import ports_as_list
from ospd.misc import get_udp_port_list
from ospd.misc import get_tcp_port_list
from ospd.misc import port_list_compress


class FullTest(unittest.TestCase):
    def test_tcp_ports(self):
        """ Test only tcp ports."""
        tports, uports = ports_as_list('T:1-10,30,31')
        self.assertFalse(tports is None)
        self.assertEqual(len(uports), 0)
        self.assertEqual(len(tports), 12)
        for i in range(1, 10):
            self.assertTrue(i in tports)
        self.assertTrue(30 in tports)
        self.assertTrue(31 in tports)

    def test_udp_ports(self):
        """ Test only udp ports."""
        tports, uports = ports_as_list('U:1-10')
        self.assertFalse(uports is None)
        self.assertEqual(len(tports), 0)
        self.assertEqual(len(uports), 10)
        for i in range(1, 10):
            self.assertTrue(i in uports)

    def test_both_ports(self):
        """ Test tcp und udp ports."""
        tports, uports = ports_as_list('T:1-10, U:1-10')
        self.assertFalse(tports is None)
        self.assertFalse(uports is None)
        self.assertEqual(len(tports), 10)
        self.assertEqual(len(uports), 10)
        for i in range(1, 10):
            self.assertTrue(i in tports)
            self.assertTrue(i in uports)
        self.assertFalse(0 in uports)

    def test_both_ports_udp_first(self):
        """ Test tcp und udp ports, but udp listed first."""
        tports, uports = ports_as_list('U:20-30, T:1-10')
        self.assertFalse(tports is None)
        self.assertFalse(uports is None)
        self.assertEqual(len(tports), 10)
        self.assertEqual(len(uports), 11)
        for i in range(1, 10):
            self.assertTrue(i in tports)
        for i in range(20, 30):
            self.assertTrue(i in uports)

    def test_not_spec_type_ports(self):
        """ Test port list without specific type. """
        tports, uports = ports_as_list('51-60')
        self.assertFalse(tports is None)
        self.assertEqual(len(uports), 0)
        self.assertEqual(len(tports), 10)
        for i in range(51, 60):
            self.assertTrue(i in tports)

    def test_invalid_char_port(self):
        """ Test list with a false char. """
        tports, uports = ports_as_list('R:51-60')
        self.assertTrue(tports is None)
        self.assertTrue(uports is None)

    def test_empty_port(self):
        """ Test an empty port list. """
        tports, uports = ports_as_list('')
        self.assertTrue(tports is None)
        self.assertTrue(uports is None)

    def test_get_spec_type_ports(self):
        """ Test get specific type ports."""
        uports = get_udp_port_list('U:9392,9393T:22')
        self.assertEqual(len(uports), 2)
        self.assertTrue(9392 in uports)
        tports = get_tcp_port_list('U:9392T:80,22,443')
        self.assertEqual(len(tports), 3)
        self.assertTrue(22 in tports)
        self.assertTrue(80 in tports)
        self.assertTrue(443 in tports)

    def test_malformed_port_string(self):
        """ Test different malformed port list. """
        tports, uports = ports_as_list('TU:1-2')
        self.assertTrue(tports is None)
        self.assertTrue(uports is None)

        tports, uports = ports_as_list('U1-2')
        self.assertTrue(tports is None)
        self.assertTrue(uports is None)

        tports, uports = ports_as_list('U:1-2t:22')
        self.assertTrue(tports is None)
        self.assertTrue(uports is None)

        tports, uports = ports_as_list('U1-2,T22')
        self.assertTrue(tports is None)
        self.assertTrue(uports is None)

        tports, uports = ports_as_list('U:1-2,U:22')
        self.assertTrue(tports is None)
        self.assertTrue(uports is None)

    def test_compress_list(self):
        """ Test different malformed port list. """
        port_list = [1, 2, 3, 4, 5, 8, 9, 10, 22, 24, 29, 30]
        string = port_list_compress(port_list)
        self.assertEqual(string, '1-5,8-10,22,24,29-30')
