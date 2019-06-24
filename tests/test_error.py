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

""" Test module for OspdCommandError class
"""

import unittest

from ospd.error import OspdCommandError


class OspdCommandErrorTestCase(unittest.TestCase):
    def test_default_params(self):
        e = OspdCommandError('message')

        self.assertEqual('message', e.message)
        self.assertEqual(400, e.status)
        self.assertEqual('osp', e.command)

    def test_constructor(self):
        e = OspdCommandError('message', 'command', '304')

        self.assertEqual('message', e.message)
        self.assertEqual('command', e.command)
        self.assertEqual('304', e.status)

    def test_string_conversion(self):
        e = OspdCommandError('message foo bar', 'command', '304')

        self.assertEqual('message foo bar', str(e))

    def test_as_xml(self):
        e = OspdCommandError('message')

        self.assertEqual(
            b'<osp_response status="400" status_text="message" />', e.as_xml()
        )
