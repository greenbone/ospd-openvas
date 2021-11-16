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

from unittest import TestCase

from ospd.command.registry import get_commands, register_command, remove_command


COMMAND_NAMES = [
    "help",
    "get_version",
    "get_performance",
    "get_scanner_details",
    "delete_scan",
    "get_vts",
    "stop_scan",
    "get_scans",
    "start_scan",
    "get_memory_usage",
]


class RegistryTestCase(TestCase):
    def test_available_commands(self):
        commands = get_commands()

        self.assertEqual(len(COMMAND_NAMES), len(commands))

        c_list = [c.name for c in commands]

        self.assertListEqual(COMMAND_NAMES, c_list)

    def test_register_command(self):
        commands = get_commands()
        before = len(commands)

        class Foo:
            name = 'foo'

        register_command(Foo)

        commands = get_commands()
        after = len(commands)

        try:
            self.assertEqual(before + 1, after)

            c_dict = {c.name: c for c in commands}

            self.assertIn('foo', c_dict)
            self.assertIs(c_dict['foo'], Foo)
        finally:
            remove_command(Foo)

        commands = get_commands()
        after2 = len(commands)

        self.assertEqual(before, after2)

        c_dict = {c.name: c for c in commands}
        self.assertNotIn('foo', c_dict)
