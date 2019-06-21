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

""" Test suites for Target manipulations.
"""

import unittest

from ospd.misc import (
    target_str_to_list,
    get_hostname_by_address,
    is_valid_address,
)


class ConvertTargetListsTestCase(unittest.TestCase):
    def test_24_net(self):
        addresses = target_str_to_list('195.70.81.0/24')
        self.assertFalse(addresses is None)
        self.assertEqual(len(addresses), 254)
        for i in range(1, 255):
            self.assertTrue('195.70.81.%d' % i in addresses)

    def test_range(self):
        addresses = target_str_to_list('195.70.81.1-10')
        self.assertFalse(addresses is None)
        self.assertEqual(len(addresses), 10)
        for i in range(1, 10):
            self.assertTrue('195.70.81.%d' % i in addresses)

    def test_get_hostname_by_address(self):
        hostname = get_hostname_by_address('127.0.0.1')
        self.assertEqual(hostname, 'localhost')

        hostname = get_hostname_by_address('')
        self.assertEqual(hostname, '')

        hostname = get_hostname_by_address('127.0.0.1111')
        self.assertEqual(hostname, '')

    def test_is_valid_address(self):
        self.assertFalse(is_valid_address(None))
        self.assertFalse(is_valid_address(''))
        self.assertFalse(is_valid_address('foo'))
        self.assertFalse(is_valid_address('127.0.0.1111'))
        self.assertFalse(is_valid_address('127.0.0,1'))

        self.assertTrue(is_valid_address('127.0.0.1'))
        self.assertTrue(is_valid_address('192.168.0.1'))
        self.assertTrue(is_valid_address('::1'))
        self.assertTrue(is_valid_address('fc00::'))
        self.assertTrue(is_valid_address('fec0::'))
        self.assertTrue(
            is_valid_address('2001:0db8:85a3:08d3:1319:8a2e:0370:7344')
        )
