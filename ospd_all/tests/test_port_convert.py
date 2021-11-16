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

""" Test suites for Port manipulation.
"""

import unittest

from ospd.network import (
    ports_as_list,
    get_udp_port_list,
    get_tcp_port_list,
    port_list_compress,
)


class ConvertPortTestCase(unittest.TestCase):
    def test_tcp_ports(self):
        """Test only tcp ports."""
        tports, uports = ports_as_list('T:1-10,30,31')

        self.assertIsNotNone(tports)
        self.assertEqual(len(uports), 0)
        self.assertEqual(len(tports), 12)

        for i in range(1, 10):
            self.assertIn(i, tports)

        self.assertIn(30, tports)
        self.assertIn(31, tports)

    def test_udp_ports(self):
        """Test only udp ports."""
        tports, uports = ports_as_list('U:1-10')

        self.assertIsNotNone(uports)
        self.assertEqual(len(tports), 0)
        self.assertEqual(len(uports), 10)

        for i in range(1, 10):
            self.assertIn(i, uports)

    def test_both_ports(self):
        """Test tcp und udp ports."""
        tports, uports = ports_as_list('T:1-10, U:1-10')

        self.assertIsNotNone(tports)
        self.assertIsNotNone(uports)

        self.assertEqual(len(tports), 10)
        self.assertEqual(len(uports), 10)

        for i in range(1, 10):
            self.assertIn(i, tports)
            self.assertIn(i, uports)

        self.assertNotIn(0, uports)

    def test_both_ports_udp_first(self):
        """Test tcp und udp ports, but udp listed first."""
        tports, uports = ports_as_list('U:20-30, T:1-10')

        self.assertIsNotNone(tports)
        self.assertIsNotNone(uports)

        self.assertEqual(len(tports), 10)
        self.assertEqual(len(uports), 11)

        for i in range(1, 10):
            self.assertIn(i, tports)

        for i in range(20, 30):
            self.assertIn(i, uports)

    def test_not_spec_type_ports(self):
        """Test port list without specific type."""
        tports, uports = ports_as_list('51-60')

        self.assertIsNotNone(tports)
        self.assertEqual(len(uports), 0)
        self.assertEqual(len(tports), 10)

        for i in range(51, 60):
            self.assertIn(i, tports)

    def test_invalid_char_port(self):
        """Test list with a false char."""
        tports, uports = ports_as_list('R:51-60')

        self.assertIsNone(tports)
        self.assertIsNone(uports)

    def test_empty_port(self):
        """Test an empty port list."""
        tports, uports = ports_as_list('')

        self.assertIsNone(tports)
        self.assertIsNone(uports)

    def test_get_spec_type_ports(self):
        """Test get specific type ports."""
        uports = get_udp_port_list('U:9392,9393T:22')

        self.assertEqual(len(uports), 2)
        self.assertIn(9392, uports)

        tports = get_tcp_port_list('U:9392T:80,22,443')

        self.assertEqual(len(tports), 3)
        self.assertIn(22, tports)
        self.assertIn(80, tports)
        self.assertIn(443, tports)

    def test_malformed_port_string(self):
        """Test different malformed port list."""
        tports, uports = ports_as_list('TU:1-2')

        self.assertIsNone(tports)
        self.assertIsNone(uports)

        tports, uports = ports_as_list('U1-2')
        self.assertIsNone(tports)
        self.assertIsNone(uports)

        tports, uports = ports_as_list('U:1-2t:22')
        self.assertIsNone(tports)
        self.assertIsNone(uports)

        tports, uports = ports_as_list('U1-2,T22')
        self.assertIsNone(tports)
        self.assertIsNone(uports)

        tports, uports = ports_as_list('U:1-2,U:22')
        self.assertIsNone(tports)
        self.assertIsNone(uports)

    def test_compress_list(self):
        """Test different malformed port list."""
        port_list = [1, 2, 3, 4, 5, 8, 9, 10, 22, 24, 29, 30]
        string = port_list_compress(port_list)

        self.assertEqual(string, '1-5,8-10,22,24,29-30')
