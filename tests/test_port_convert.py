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
    valid_port_list,
)

class ValidatePortList(unittest.TestCase):
    def test_valid_port_list_no_range(self):
        """ Test no port list provided """
        self.assertFalse(valid_port_list(None))
        self.assertFalse(valid_port_list(""))

    def test_valid_port_list_0_end(self):
        self.assertFalse(valid_port_list("\0"))
        self.assertFalse(valid_port_list("T:1-5,7,9,U:1-3,5,7,9,\\0"))

    def test_valid_port_list_newline_between_range(self):
        self.assertFalse(valid_port_list("\nT:1-\n5,7,9,\nU:1-3,5\n,7,9\n"))

    def test_valid_port_out_of_range(self):
        self.assertFalse(valid_port_list("0"))
        self.assertFalse(valid_port_list("-9"))
        self.assertFalse(valid_port_list("1,0,6,7"))
        self.assertFalse(valid_port_list("2,-9,4"))
        self.assertFalse(valid_port_list("90000"))

    def test_valid_port_illegal_ranges(self):
        self.assertFalse(valid_port_list ("T:-"))
        self.assertFalse(valid_port_list ("T:-9"))
        self.assertFalse(valid_port_list ("T:0-"))
        self.assertFalse(valid_port_list ("T:0-9"))
        self.assertFalse(valid_port_list ("T:90000-"))
        self.assertFalse(valid_port_list ("T:90000-90010"))
        self.assertFalse(valid_port_list ("T:9-\\0"))
        self.assertFalse(valid_port_list ("T:9-0"))
        self.assertFalse(valid_port_list ("T:9-90000"))
        self.assertFalse(valid_port_list ("T:100-9"))
        self.assertFalse(valid_port_list ("0-"))
        self.assertFalse(valid_port_list ("0-9"))
        self.assertFalse(valid_port_list ("9-"))
        self.assertFalse(valid_port_list ("9-\\0"))
        self.assertFalse(valid_port_list ("9-8"))
        self.assertFalse(valid_port_list ("90000-90010"))
        self.assertFalse(valid_port_list ("100-9"))
        self.assertFalse(valid_port_list ("T,U"))
        self.assertFalse(valid_port_list ("T  :\n: 1-2,U"))
        self.assertFalse(valid_port_list ("T  :: 1-2,U"))
        self.assertFalse(valid_port_list ("T:2=2"))
        self.assertFalse(valid_port_list ("T:1.2-5,4.5"))

    def test_valid_port_legal_ports(self):
        self.assertTrue(valid_port_list("6,6,6,6,10,20"))
        self.assertTrue(valid_port_list("T:7, U:7"))
        self.assertTrue(valid_port_list("T:7, U:9"))
        self.assertTrue(valid_port_list("9"))
        self.assertTrue(valid_port_list("U:,T:"))
        self.assertTrue(valid_port_list("1,2,,,,,,,\n\n\n\n\n\n,,,5"))
        self.assertTrue(valid_port_list("T:1-5,7,9,U:1-3,5,7,9"))
        self.assertTrue(valid_port_list("6-9,7,7,10-20,20"))

    def test_valid_port_new_lines_as_commas(self):
        self.assertTrue(valid_port_list("1,2,\n,\n4,6"))
        self.assertTrue(valid_port_list("T:1-5,7,9,\nU:1-3,5\n,7,9"))

    def test_valid_port_allow_white_spaces(self):
        self.assertTrue(valid_port_list("   T: 1 -5,  7   ,9, \nU   :1-  3,5  \n,7,9"))
    
class ConvertPortTestCase(unittest.TestCase):
    def test_tcp_ports(self):
        """ Test only tcp ports."""
        tports, uports = ports_as_list('T:1-10,30,31')

        self.assertIsNotNone(tports)
        self.assertEqual(len(uports), 0)
        self.assertEqual(len(tports), 12)

        for i in range(1, 10):
            self.assertIn(i, tports)

        self.assertIn(30, tports)
        self.assertIn(31, tports)

    def test_udp_ports(self):
        """ Test only udp ports."""
        tports, uports = ports_as_list('U:1-10')

        self.assertIsNotNone(uports)
        self.assertEqual(len(tports), 0)
        self.assertEqual(len(uports), 10)

        for i in range(1, 10):
            self.assertIn(i, uports)

    def test_both_ports(self):
        """ Test tcp und udp ports."""
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
        """ Test tcp und udp ports, but udp listed first."""
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
        """ Test port list without specific type. """
        tports, uports = ports_as_list('51-60')

        self.assertIsNotNone(tports)
        self.assertEqual(len(uports), 0)
        self.assertEqual(len(tports), 10)

        for i in range(51, 60):
            self.assertIn(i, tports)

    def test_invalid_char_port(self):
        """ Test list with a false char. """
        tports, uports = ports_as_list('R:51-60')

        self.assertIsNone(tports)
        self.assertIsNone(uports)

    def test_empty_port(self):
        """ Test an empty port list. """
        tports, uports = ports_as_list('')

        self.assertIsNone(tports)
        self.assertIsNone(uports)

    def test_get_spec_type_ports(self):
        """ Test get specific type ports."""
        uports = get_udp_port_list('U:9392,9393T:22')

        self.assertEqual(len(uports), 2)
        self.assertIn(9392, uports)

        tports = get_tcp_port_list('U:9392T:80,22,443')

        self.assertEqual(len(tports), 3)
        self.assertIn(22, tports)
        self.assertIn(80, tports)
        self.assertIn(443, tports)

    def test_malformed_port_string(self):
        """ Test different malformed port list. """
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
        """ Test different malformed port list. """
        port_list = [1, 2, 3, 4, 5, 8, 9, 10, 22, 24, 29, 30]
        string = port_list_compress(port_list)

        self.assertEqual(string, '1-5,8-10,22,24,29-30')
