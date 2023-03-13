# Copyright (C) 2014-2021 Greenbone AG
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

# pylint: disable=invalid-name

from collections import OrderedDict
import logging

from unittest import TestCase
from unittest.mock import Mock

from xml.etree.ElementTree import Element, tostring, fromstring

from ospd.xml import (
    elements_as_text,
    escape_ctrl_chars,
)
from ospd.xmlvt import (
    XmlStringVTHelper,
)
from .dummydaemon import DummyDaemon
from .helper import assert_called_once

logger = logging.getLogger(__name__)


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


class VTsText(TestCase):
    def test_get_custom_xml(self):
        out = (
            '<custom>'
            '<required_ports>Services/www, 80</required_ports>'
            '<category>3</category>'
            '<excluded_keys>Settings/disable_cgi_scanning</excluded_keys>'
            '<family>Product detection</family>'
            '<filename>mantis_detect.nasl</filename>'
            '<timeout>0</timeout>'
            '</custom>'
        )
        w = DummyDaemon()
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']

        xml_str = XmlStringVTHelper()
        res = xml_str.get_custom_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt.get('custom')
        )
        self.assertEqual(len(res), len(out))

    def test_get_custom_xml_failed(self):
        logging.Logger.warning = Mock()

        custom = {'a': "\u0006"}
        xml_str = XmlStringVTHelper()
        xml_str.get_custom_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', custom=custom
        )

        assert_called_once(logging.Logger.warning)

    def test_get_severities_xml(self):
        w = DummyDaemon()

        out = (
            '<severities>'
            '<severity type="cvss_base_v2">'
            '<value>AV:N/AC:L/Au:N/C:N/I:N/A:N</value>'
            '<origin>Greenbone</origin>'
            '<date>1237458156</date>'
            '</severity>'
            '</severities>'
        )
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        severities = vt.get('severities')
        xml_str = XmlStringVTHelper()
        res = xml_str.get_severities_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', severities
        )

        self.assertEqual(res, out)

    def test_get_severities_xml_failed(self):
        logging.Logger.warning = Mock()

        sever = {'severity_base_vector': "\u0006"}
        xml_str = XmlStringVTHelper()
        xml_str.get_severities_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', severities=sever
        )

        assert_called_once(logging.Logger.warning)

    def test_get_params_xml(self):
        w = DummyDaemon()
        out = (
            '<params>'
            '<param type="checkbox" id="2">'
            '<name>Do not randomize the  order  in  which ports are '
            'scanned</name>'
            '<default>no</default>'
            '</param>'
            '<param type="entry" id="1">'
            '<name>Data length :</name>'
            '</param>'
            '</params>'
        )

        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        params = vt.get('vt_params')
        xml_str = XmlStringVTHelper()
        res = xml_str.get_params_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', params
        )

        self.assertEqual(len(res), len(out))

    def test_get_params_xml_failed(self):
        logging.Logger.warning = Mock()

        params = {
            '1': {
                'id': '1',
                'type': 'entry',
                'default': '\u0006',
                'name': 'dns-fuzz.timelimit',
                'description': 'Description',
            }
        }
        xml_str = XmlStringVTHelper()
        xml_str.get_params_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', params)

        assert_called_once(logging.Logger.warning)

    def test_get_refs_xml(self):
        w = DummyDaemon()

        out = '<refs><ref type="url" id="http://www.mantisbt.org/"/></refs>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        refs = vt.get('vt_refs')
        xml_str = XmlStringVTHelper()
        res = xml_str.get_refs_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', refs
        )

        self.assertEqual(res, out)

    def test_get_dependencies_xml(self):
        out = (
            '<dependencies>'
            '<dependency vt_id="1.3.6.1.4.1.25623.1.2.3.4"/>'
            '<dependency vt_id="1.3.6.1.4.1.25623.4.3.2.1"/>'
            '</dependencies>'
        )
        dep = ['1.3.6.1.4.1.25623.1.2.3.4', '1.3.6.1.4.1.25623.4.3.2.1']
        xml_str = XmlStringVTHelper()
        res = xml_str.get_dependencies_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', dep
        )

        self.assertEqual(res, out)

    def test_get_dependencies_xml_missing_dep(self):
        out = (
            '<dependencies>'
            '<dependency vt_id="1.3.6.1.4.1.25623.1.2.3.4"/>'
            '</dependencies>'
        )
        dep = ['1.3.6.1.4.1.25623.1.2.3.4', 'file_name.nasl']
        xml_str = XmlStringVTHelper()
        res = xml_str.get_dependencies_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', dep
        )

        self.assertEqual(res, out)

    def test_get_dependencies_xml_failed(self):
        logging.Logger.error = Mock()

        dep = ["\u0006"]
        xml_str = XmlStringVTHelper()
        xml_str.get_dependencies_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt_dependencies=dep
        )

        assert_called_once(logging.Logger.error)

    def test_get_ctime_xml(self):
        w = DummyDaemon()

        out = '<creation_time>1237458156</creation_time>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        ctime = vt.get('creation_time')
        xml_str = XmlStringVTHelper()
        res = xml_str.get_creation_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', ctime
        )

        self.assertEqual(res, out)

    def test_get_ctime_xml_failed(self):
        logging.Logger.warning = Mock()

        ctime = '\u0006'
        xml_str = XmlStringVTHelper()
        xml_str.get_creation_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt_creation_time=ctime
        )

        assert_called_once(logging.Logger.warning)

    def test_get_mtime_xml(self):
        w = DummyDaemon()

        out = '<modification_time>1533906565</modification_time>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        mtime = vt.get('modification_time')
        xml_str = XmlStringVTHelper()
        res = xml_str.get_modification_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', mtime
        )

        self.assertEqual(res, out)

    def test_get_mtime_xml_failed(self):
        logging.Logger.warning = Mock()

        mtime = '\u0006'
        xml_str = XmlStringVTHelper()
        xml_str.get_modification_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', mtime
        )

        assert_called_once(logging.Logger.warning)

    def test_get_summary_xml(self):
        w = DummyDaemon()

        out = '<summary>some summary</summary>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        summary = vt.get('summary')
        xml_str = XmlStringVTHelper()
        res = xml_str.get_summary_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', summary
        )

        self.assertEqual(res, out)

    def test_get_summary_xml_failed(self):
        summary = '\u0006 > <'
        logging.Logger.warning = Mock()
        xml_str = XmlStringVTHelper()
        xml_str.get_summary_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', summary
        )

        assert_called_once(logging.Logger.warning)

    def test_get_impact_xml(self):
        w = DummyDaemon()

        out = '<impact>some impact</impact>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        impact = vt.get('impact')
        xml_str = XmlStringVTHelper()
        res = xml_str.get_impact_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', impact
        )

        self.assertEqual(res, out)

    def test_get_impact_xml_failed(self):
        logging.Logger.warning = Mock()

        impact = '\u0006'
        xml_str = XmlStringVTHelper()
        xml_str.get_impact_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', impact)

        assert_called_once(logging.Logger.warning)

    def test_get_insight_xml(self):
        w = DummyDaemon()

        out = '<insight>some insight</insight>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        insight = vt.get('insight')
        xml_str = XmlStringVTHelper()
        res = xml_str.get_insight_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', insight
        )

        self.assertEqual(res, out)

    def test_get_insight_xml_failed(self):
        logging.Logger.warning = Mock()

        insight = '\u0006'
        xml_str = XmlStringVTHelper()
        xml_str.get_insight_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', insight
        )

        assert_called_once(logging.Logger.warning)

    def test_get_solution_xml(self):
        w = DummyDaemon()

        out = (
            '<solution type="WillNotFix" method="DebianAPTUpgrade">'
            'some solution'
            '</solution>'
        )
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        solution = vt.get('solution')
        solution_type = vt.get('solution_type')
        solution_method = vt.get('solution_method')

        xml_str = XmlStringVTHelper()
        res = xml_str.get_solution_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061',
            solution,
            solution_type,
            solution_method,
        )

        self.assertEqual(res, out)

    def test_get_solution_xml_failed(self):
        logging.Logger.warning = Mock()

        solution = '\u0006'
        xml_str = XmlStringVTHelper()
        xml_str.get_solution_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', solution
        )

        assert_called_once(logging.Logger.warning)

    def test_get_detection_xml(self):
        w = DummyDaemon()

        out = '<detection qod_type="remote_banner"/>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        detection_type = vt.get('qod_type')

        xml_str = XmlStringVTHelper()
        res = xml_str.get_detection_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', qod_type=detection_type
        )

        self.assertEqual(res, out)

    def test_get_detection_xml_failed(self):
        logging.Logger.warning = Mock()

        detection = '\u0006'
        xml_str = XmlStringVTHelper()
        xml_str.get_detection_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', detection
        )

        assert_called_once(logging.Logger.warning)

    def test_get_affected_xml(self):
        w = DummyDaemon()
        out = '<affected>some affection</affected>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        affected = vt.get('affected')

        xml_str = XmlStringVTHelper()
        res = xml_str.get_affected_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', affected=affected
        )

        self.assertEqual(res, out)

    def test_get_affected_xml_failed(self):
        logging.Logger.warning = Mock()

        affected = "\u0006" + "affected"
        xml_str = XmlStringVTHelper()
        xml_str.get_affected_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', affected=affected
        )

        assert_called_once(logging.Logger.warning)
