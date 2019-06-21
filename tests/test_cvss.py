# Copyright (C) 2015-2018 Greenbone Networks GmbH
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

""" Test module for cvss scoring calculation
"""

import unittest

from ospd.cvss import CVSS


class CvssTestCase(unittest.TestCase):
    def test_cvssv2(self):
        vector = 'AV:A/AC:L/Au:S/C:P/I:P/A:P'
        cvss_base = CVSS.cvss_base_v2_value(vector)

        self.assertEqual(cvss_base, 5.2)

    def test_cvssv3(self):
        vector = 'CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N'
        cvss_base = CVSS.cvss_base_v3_value(vector)

        self.assertEqual(cvss_base, 3.8)
