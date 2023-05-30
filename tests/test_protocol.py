# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from ospd.protocol import RequestParser


class RequestParserTestCase(unittest.TestCase):
    def test_parse(self):
        parser = RequestParser()
        self.assertFalse(parser.has_ended(b'<foo><bar>'))
        self.assertFalse(parser.has_ended(b'</bar>'))
        self.assertTrue(parser.has_ended(b'</foo>'))
