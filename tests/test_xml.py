# Copyright (C) 2020 Greenbone Networks GmbH
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

from collections import OrderedDict

from unittest import TestCase

from ospd.xml import elements_as_text


class ElementsAsText(TestCase):
    def test_simple_element(self):
        elements = {'foo': 'bar'}
        text = elements_as_text(elements)

        self.assertEqual(text, '\t  foo                    bar\n')

    def test_simple_elements(self):
        elements = OrderedDict([('foo', 'bar'), ('lorem', 'ipsum')])
        text = elements_as_text(elements)

        self.assertEqual(
            text,
            '\t  foo                    bar\n'
            '\t  lorem                  ipsum\n',
        )

    def test_elements(self):
        elements = OrderedDict(
            [
                ('foo', 'bar'),
                (
                    'lorem',
                    OrderedDict(
                        [
                            ('dolor', 'sit amet'),
                            ('consectetur', 'adipiscing elit'),
                        ]
                    ),
                ),
            ]
        )
        text = elements_as_text(elements)

        self.assertEqual(
            text,
            '\t  foo                    bar\n'
            '\t  lorem                  \n'
            '\t    dolor                  sit amet\n'
            '\t    consectetur            adipiscing elit\n',
        )
