# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Test module for cvss scoring calculation"""

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

    def test_cvssv2_optional_metrics(self):
        vector = 'AV:A/AC:L/Au:S/C:P/I:P/A:P/E:F'
        cvss_base = CVSS.cvss_base_v2_value(vector)

        self.assertEqual(cvss_base, None)

    def test_cvssv3_optional_metrics(self):
        vector = 'CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N/E:X'
        cvss_base = CVSS.cvss_base_v3_value(vector)

        self.assertEqual(cvss_base, None)
