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

from collections import OrderedDict

from unittest import TestCase

from xml.etree.ElementTree import Element, tostring, fromstring

from ospd.xml import elements_as_text, escape_ctrl_chars


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


class EscapeText(TestCase):
    def test_escape_xml_valid_text(self):
        text = 'this is a valid xml'
        res = escape_ctrl_chars(text)

        self.assertEqual(text, res)

    def test_escape_xml_invalid_char(self):
        text = 'End of transmission is not printable \x04.'
        res = escape_ctrl_chars(text)
        self.assertEqual(res, 'End of transmission is not printable \\x0004.')

        # Create element
        elem = Element('text')
        elem.text = res
        self.assertEqual(
            tostring(elem),
            b'<text>End of transmission is not printable \\x0004.</text>',
        )

        # The string format of the element does not break the xml.
        elem_as_str = tostring(elem, encoding='utf-8')
        new_elem = fromstring(elem_as_str)
        self.assertEqual(
            b'<text>' + new_elem.text.encode('utf-8') + b'</text>', elem_as_str
        )

    def test_escape_xml_printable_char(self):
        text = 'Latin Capital Letter A With Circumflex \xc2 is printable.'
        res = escape_ctrl_chars(text)
        self.assertEqual(
            res, 'Latin Capital Letter A With Circumflex Â is printable.'
        )

        # Create the element
        elem = Element('text')
        elem.text = res
        self.assertEqual(
            tostring(elem),
            b'<text>Latin Capital Letter A With Circumflex &#194; is '
            b'printable.</text>',
        )

        # The string format of the element does not break the xml
        elem_as_str = tostring(elem, encoding='utf-8')
        new_elem = fromstring(elem_as_str)
        self.assertEqual(
            b'<text>' + new_elem.text.encode('utf-8') + b'</text>', elem_as_str
        )
