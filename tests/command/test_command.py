# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest import TestCase

from ospd.command.registry import get_commands, remove_command
from ospd.command.command import BaseCommand


class BaseCommandTestCase(TestCase):
    def test_auto_register(self):
        commands = get_commands()
        before = len(commands)

        class Foo(BaseCommand):
            name = "foo"

            def handle_xml(self, xml):
                pass

        after = len(commands)

        try:
            self.assertEqual(before + 1, after)

            c_dict = {c.name: c for c in commands}

            self.assertIn('foo', c_dict)
            self.assertIs(c_dict['foo'], Foo)
        finally:
            remove_command(Foo)

    def test_basic_properties(self):
        class Foo(BaseCommand):
            name = "foo"
            attributes = {'lorem': 'ipsum'}
            elements = {'foo': 'bar'}
            description = 'bar'

            def handle_xml(self, xml):
                pass

        try:
            f = Foo({})

            self.assertEqual(f.get_name(), 'foo')
            self.assertEqual(f.get_description(), 'bar')
            self.assertEqual(f.get_attributes(), {'lorem': 'ipsum'})
            self.assertEqual(f.get_elements(), {'foo': 'bar'})
        finally:
            remove_command(Foo)

    def test_as_dict(self):
        class Foo(BaseCommand):
            name = "foo"
            attributes = {'lorem': 'ipsum'}
            elements = {'foo': 'bar'}
            description = 'bar'

            def handle_xml(self, xml):
                pass

        try:
            f = Foo({})

            f_dict = f.as_dict()

            self.assertEqual(f_dict['name'], 'foo')
            self.assertEqual(f_dict['description'], 'bar')
            self.assertEqual(f_dict['attributes'], {'lorem': 'ipsum'})
            self.assertEqual(f_dict['elements'], {'foo': 'bar'})
        finally:
            remove_command(Foo)
