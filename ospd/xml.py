# Copyright (C) 2014-2018 Greenbone Networks GmbH
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
        result_xml.set(name, str(value))
    result_xml.text = result['value']
    return result_xml


def simple_response_str(command, status, status_text, content=""):
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
        response.set(name, str(value))
    if isinstance(content, list):
        for elem in content:
            response.append(elem)
    elif isinstance(content, Element):
        response.append(content)
    else:
        response.text = content
    return tostring(response)
