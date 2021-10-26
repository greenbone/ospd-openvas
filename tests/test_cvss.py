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
