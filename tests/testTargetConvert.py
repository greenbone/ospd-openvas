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

from ospd.misc import target_str_to_list

class testTargetLists(unittest.TestCase):

    def test24Net(self):
        addresses = target_str_to_list('195.70.81.0/24')
        self.assertFalse(addresses is None)
        self.assertEqual(len(addresses), 254)
        for i in range(1, 255):
            self.assertTrue('195.70.81.%d' % i in addresses)
       
        
