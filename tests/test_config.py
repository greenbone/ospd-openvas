# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Test module for configuration."""

import unittest

from ospd.config import strtoboolean


class StrtobooleanTestCase(unittest.TestCase):
    def test_trues(self) -> None:
        self.assertEqual(True, strtoboolean("true"))
        self.assertEqual(True, strtoboolean("True"))
        self.assertEqual(True, strtoboolean("TRUE"))
        self.assertEqual(True, strtoboolean("yes"))
        self.assertEqual(True, strtoboolean("Yes"))
        self.assertEqual(True, strtoboolean("YES"))
        self.assertEqual(True, strtoboolean("on"))
        self.assertEqual(True, strtoboolean("On"))
        self.assertEqual(True, strtoboolean("ON"))
        self.assertEqual(True, strtoboolean("1"))

    def test_falses(self) -> None:
        self.assertEqual(False, strtoboolean("false"))
        self.assertEqual(False, strtoboolean("False"))
        self.assertEqual(False, strtoboolean("FALSE"))
        self.assertEqual(False, strtoboolean("no"))
        self.assertEqual(False, strtoboolean("No"))
        self.assertEqual(False, strtoboolean("NO"))
        self.assertEqual(False, strtoboolean("off"))
        self.assertEqual(False, strtoboolean("Off"))
        self.assertEqual(False, strtoboolean("OFF"))
        self.assertEqual(False, strtoboolean("0"))

    def test_illegals(self) -> None:
        with self.assertRaises(ValueError):
            strtoboolean("fudge")
        with self.assertRaises(ValueError):
            strtoboolean("lemon")
        with self.assertRaises(ValueError):
            strtoboolean("melon")
