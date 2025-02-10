# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Test module for OspdCommandError class"""

import unittest

from ospd.errors import OspdError, OspdCommandError, RequiredArgument


class OspdCommandErrorTestCase(unittest.TestCase):
    def test_is_ospd_error(self):
        e = OspdCommandError('message')
        self.assertIsInstance(e, OspdError)

    def test_default_params(self):
        e = OspdCommandError('message')

        self.assertEqual('message', e.message)
        self.assertEqual(400, e.status)
        self.assertEqual('osp', e.command)

    def test_constructor(self):
        e = OspdCommandError('message', 'command', 304)

        self.assertEqual('message', e.message)
        self.assertEqual('command', e.command)
        self.assertEqual(304, e.status)

    def test_string_conversion(self):
        e = OspdCommandError('message foo bar', 'command', 304)

        self.assertEqual('message foo bar', str(e))

    def test_as_xml(self):
        e = OspdCommandError('message')

        self.assertEqual(
            b'<osp_response status="400" status_text="message" />', e.as_xml()
        )


class RequiredArgumentTestCase(unittest.TestCase):
    def test_raise_exception(self):
        with self.assertRaises(RequiredArgument) as cm:
            raise RequiredArgument('foo', 'bar')

        ex = cm.exception
        self.assertEqual(ex.function, 'foo')
        self.assertEqual(ex.argument, 'bar')

    def test_string_conversion(self):
        ex = RequiredArgument('foo', 'bar')
        self.assertEqual(str(ex), 'foo: Argument bar is required')

    def test_is_ospd_error(self):
        e = RequiredArgument('foo', 'bar')
        self.assertIsInstance(e, OspdError)
