# Copyright (C) 2014-2020 Greenbone Networks GmbH
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

""" OSP XML utils class.
"""


from typing import List, Dict, Any, Union

from xml.sax.saxutils import escape
from xml.etree.ElementTree import tostring, Element

from ospd.misc import ResultType


def get_result_xml(result):
    """ Formats a scan result to XML format.

    Arguments:
        result (dict): Dictionary with a scan result.

    Return:
        Result as xml element object.
    """
    result_xml = Element('result')
    for name, value in [
        ('name', result['name']),
        ('type', ResultType.get_str(result['type'])),
        ('severity', result['severity']),
        ('host', result['host']),
        ('hostname', result['hostname']),
        ('test_id', result['test_id']),
        ('port', result['port']),
        ('qod', result['qod']),
    ]:
        result_xml.set(name, escape(str(value)))
    result_xml.text = result['value']

    return result_xml


def simple_response_str(
    command: str,
    status: int,
    status_text: str,
    content: Union[str, Element, List[str], List[Element]] = "",
) -> bytes:
    """ Creates an OSP response XML string.

    Arguments:
        command (str): OSP Command to respond to.
        status (int): Status of the response.
        status_text (str): Status text of the response.
        content (str): Text part of the response XML element.

    Return:
        String of response in xml format.
    """
    response = Element('%s_response' % command)

    for name, value in [('status', str(status)), ('status_text', status_text)]:
        response.set(name, escape(str(value)))

    if isinstance(content, list):
        for elem in content:
            if isinstance(elem, Element):
                response.append(elem)
    elif isinstance(content, Element):
        response.append(content)
    else:
        response.text = content

    return tostring(response, encoding='utf-8')


def get_elements_from_dict(data: Dict[str, Any]) -> List[Element]:
    """ Creates a list of etree elements from a dictionary

    Args:
        Dictionary of tags and their elements.

    Return:
        List of xml elements.
    """

    responses = []

    for tag, value in data.items():
        elem = Element(tag)

        if isinstance(value, dict):
            for val in get_elements_from_dict(value):
                elem.append(val)
        elif isinstance(value, list):
            elem.text = ', '.join(value)
        else:
            elem.text = value

        responses.append(elem)

    return responses


def elements_as_text(
    elements: Dict[str, Union[str, Dict]], indent: int = 2
) -> str:
    """ Returns the elements dictionary as formatted plain text. """

    text = ""
    for elename, eledesc in elements.items():
        if isinstance(eledesc, dict):
            desc_txt = elements_as_text(eledesc, indent + 2)
            desc_txt = ''.join(['\n', desc_txt])
        elif isinstance(eledesc, str):
            desc_txt = ''.join([eledesc, '\n'])
        else:
            assert False, "Only string or dictionary"

        ele_txt = "\t{0}{1: <22} {2}".format(' ' * indent, elename, desc_txt)

        text = ''.join([text, ele_txt])

    return text


class XmlStringHelper:
    """ Class with methods to help the creation of a xml object in
    string format.
    """

    def create_element(self, elem_name: str, end: bool = False) -> bytes:
        """ Get a name and create the open element of an entity.

        Arguments:
            elem_name (str): The name of the tag element.
            end (bool): Create a initial tag if False, otherwise the end tag.

        Return:
            Encoded string representing a part of an xml element.
        """
        if end:
            ret = "</%s>" % elem_name
        else:
            ret = "<%s>" % elem_name

        return ret.encode('utf-8')

    def create_response(self, command: str, end: bool = False) -> bytes:
        """ Create or end an xml response.

        Arguments:
            command (str): The name of the command for the response element.
            end (bool): Create a initial tag if False, otherwise the end tag.

        Return:
            Encoded string representing a part of an xml element.
        """
        if not command:
            return

        if end:
            return ('</%s_response>' % command).encode('utf-8')

        return ('<%s_response status="200" status_text="OK">' % command).encode(
            'utf-8'
        )

    def add_element(
        self,
        content: Union[Element, str, list],
        xml_str: bytes = None,
        end: bool = False,
    ) -> bytes:
        """Create the initial or ending tag for a subelement, or add
        one or many xml elements

        Arguments:
            content (Element, str, list): Content to add.
            xml_str (bytes): Initial string where content to be added to.
            end (bool): Create a initial tag if False, otherwise the end tag.
                        It will be added to the xml_str.

        Return:
            Encoded string representing a part of an xml element.
        """

        if not xml_str:
            xml_str = b''

        if content:
            if isinstance(content, list):
                for elem in content:
                    xml_str = xml_str + tostring(elem, encoding='utf-8')
            elif isinstance(content, Element):
                xml_str = xml_str + tostring(content, encoding='utf-8')
            else:
                if end:
                    xml_str = xml_str + self.create_element(content, False)
                else:
                    xml_str = xml_str + self.create_element(content)

        return xml_str

    def add_attr(self, tag: bytes, attribute: str, value: str = None) -> bytes:
        """ Add an attribute to the beginnig tag of an xml element.
        Arguments:
            tag (bytes): Tag to add the attrubute to.
            attribute (str): Attribute name
            value (str): Attribute value
        Return:
            Tag in encoded string format with the given attribute
        """
        if not tag:
            return None

        if not attribute:
            return tag

        if not value:
            value = ''

        return tag[:-1] + (" %s=\'%s\'>" % (attribute, value)).encode('utf-8')
