# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest import TestCase

from ospd.command.registry import get_commands, register_command, remove_command


COMMAND_NAMES = [
    "help",
    "check_feed",
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
