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

""" Helper classes for parsing and creating OSP XML requests and responses
"""

from typing import Dict, Union, List, Any

from xml.etree.ElementTree import SubElement, Element, XMLPullParser

from ospd.errors import OspdError


class RequestParser:
    def __init__(self):
        self._parser = XMLPullParser(['start', 'end'])
        self._root_element = None

    def has_ended(self, data: bytes) -> bool:
        self._parser.feed(data)

        for event, element in self._parser.read_events():
            if event == 'start' and self._root_element is None:
                self._root_element = element
            elif event == 'end' and self._root_element is not None:
                if element.tag == self._root_element.tag:
                    return True

        return False


class OspRequest:
    @staticmethod
    def process_vts_params(
        scanner_vts: Element,
    ) -> Dict[str, Union[Dict[str, str], List]]:
        """Receive an XML object with the Vulnerability Tests an their
        parameters to be use in a scan and return a dictionary.

        @param: XML element with vt subelements. Each vt has an
                id attribute. Optional parameters can be included
                as vt child.
                Example form:
                <vt_selection>
                  <vt_single id='vt1' />
                  <vt_single id='vt2'>
                    <vt_value id='param1'>value</vt_value>
                  </vt_single>
                  <vt_group filter='family=debian'/>
                  <vt_group filter='family=general'/>
                </vt_selection>

        @return: Dictionary containing the vts attribute and subelements,
                 like the VT's id and VT's parameters.
                 Example form:
                 {'vt1': {},
                  'vt2': {'value_id': 'value'},
                  'vt_groups': ['family=debian', 'family=general']}
        """
        vt_selection = {}  # type: Dict
        filters = []

        for vt in scanner_vts:
            if vt.tag == 'vt_single':
                vt_id = vt.attrib.get('id')
                vt_selection[vt_id] = {}

                for vt_value in vt:
                    if not vt_value.attrib.get('id'):
                        raise OspdError(
                            'Invalid VT preference. No attribute id'
                        )

                    vt_value_id = vt_value.attrib.get('id')
                    vt_value_value = vt_value.text if vt_value.text else ''
                    vt_selection[vt_id][vt_value_id] = vt_value_value

            if vt.tag == 'vt_group':
                vts_filter = vt.attrib.get('filter', None)

                if vts_filter is None:
                    raise OspdError('Invalid VT group. No filter given.')

                filters.append(vts_filter)

        vt_selection['vt_groups'] = filters

        return vt_selection

    @staticmethod
    def process_credentials_elements(cred_tree: Element) -> Dict:
        """Receive an XML object with the credentials to run
        a scan against a given target.

        @param:
        <credentials>
          <credential type="up" service="ssh" port="22">
            <username>scanuser</username>
            <password>mypass</password>
          </credential>
          <credential type="up" service="smb">
            <username>smbuser</username>
            <password>mypass</password>
          </credential>
        </credentials>

        @return: Dictionary containing the credentials for a given target.
                 Example form:
                 {'ssh': {'type': type,
                          'port': port,
                          'username': username,
                          'password': pass,
                        },
                  'smb': {'type': type,
                          'username': username,
                          'password': pass,
                         },
                   }
        """
        credentials = {}  # type: Dict

        for credential in cred_tree:
            service = credential.attrib.get('service')
            credentials[service] = {}
            credentials[service]['type'] = credential.attrib.get('type')

            if service == 'ssh':
                credentials[service]['port'] = credential.attrib.get('port')

            for param in credential:
                credentials[service][param.tag] = (
                    param.text if param.text else ""
                )

        return credentials

    @staticmethod
    def process_alive_test_methods(
        alive_test_tree: Element, options: Dict
    ) -> None:
        """Receive an XML object with the alive test methods to run
        a scan with. Methods are added to the options Dict.

        @param
        <alive_test_methods>
            </icmp>boolean(1 or 0)</icmp>
            </tcp_ack>boolean(1 or 0)</tcp_ack>
            </tcp_syn>boolean(1 or 0)</tcp_syn>
            </arp>boolean(1 or 0)</arp>
            </consider_alive>boolean(1 or 0)</consider_alive>
        </alive_test_methods>
        """
        for child in alive_test_tree:
            if child.tag == 'icmp':
                if child.text is not None:
                    options['icmp'] = child.text
            if child.tag == 'tcp_ack':
                if child.text is not None:
                    options['tcp_ack'] = child.text
            if child.tag == 'tcp_syn':
                if child.text is not None:
                    options['tcp_syn'] = child.text
            if child.tag == 'arp':
                if child.text is not None:
                    options['arp'] = child.text
            if child.tag == 'consider_alive':
                if child.text is not None:
                    options['consider_alive'] = child.text

    @classmethod
    def process_target_element(cls, scanner_target: Element) -> Dict:
        """Receive an XML object with the target, ports and credentials to run
        a scan against.

        Arguments:
            Single XML target element. The target has <hosts> and <ports>
            subelements. Hosts can be a single host, a host range, a
            comma-separated host list or a network address.
            <ports> and  <credentials> are optional. Therefore each
            ospd-scanner should check for a valid ones if needed.

            Example form:

            <target>
                <hosts>192.168.0.0/24</hosts>
                <ports>22</ports>
                <credentials>
                    <credential type="up" service="ssh" port="22">
                    <username>scanuser</username>
                    <password>mypass</password>
                    </credential>
                    <credential type="up" service="smb">
                    <username>smbuser</username>
                    <password>mypass</password>
                    </credential>
                </credentials>
                <alive_test></alive_test>
                <alive_test_ports></alive_test_ports>
                <reverse_lookup_only>1</reverse_lookup_only>
                <reverse_lookup_unify>0</reverse_lookup_unify>
            </target>

        Return:
            A Dict  hosts, port, {credentials}, exclude_hosts, options].

            Example form:

            {
                'hosts': '192.168.0.0/24',
                'port': '22',
                'credentials': {'smb': {'type': type,
                                        'port': port,
                                        'username': username,
                                        'password': pass,
                                        }
                                },

                'exclude_hosts': '',
                'finished_hosts': '',
                'options': {'alive_test': 'ALIVE_TEST_CONSIDER_ALIVE',
                            'alive_test_ports: '22,80,123',
                            'reverse_lookup_only': '1',
                            'reverse_lookup_unify': '0',
                            },
            }
        """
        if scanner_target:
            exclude_hosts = ''
            finished_hosts = ''
            ports = ''
            hosts = None
            credentials = {}  # type: Dict
            options = {}

            for child in scanner_target:
                if child.tag == 'hosts':
                    hosts = child.text
                if child.tag == 'exclude_hosts':
                    exclude_hosts = child.text
                if child.tag == 'finished_hosts':
                    finished_hosts = child.text
                if child.tag == 'ports':
                    ports = child.text
                if child.tag == 'credentials':
                    credentials = cls.process_credentials_elements(child)
                if child.tag == 'alive_test_methods':
                    options['alive_test_methods'] = '1'
                    cls.process_alive_test_methods(child, options)
                if child.tag == 'alive_test':
                    options['alive_test'] = child.text
                if child.tag == 'alive_test_ports':
                    options['alive_test_ports'] = child.text
                if child.tag == 'reverse_lookup_unify':
                    options['reverse_lookup_unify'] = child.text
                if child.tag == 'reverse_lookup_only':
                    options['reverse_lookup_only'] = child.text

            if hosts:
                return {
                    'hosts': hosts,
                    'ports': ports,
                    'credentials': credentials,
                    'exclude_hosts': exclude_hosts,
                    'finished_hosts': finished_hosts,
                    'options': options,
                }
            else:
                raise OspdError('No target to scan')


class OspResponse:
    @staticmethod
    def create_scanner_params_xml(scanner_params: Dict[str, Any]) -> Element:
        """ Returns the OSP Daemon's scanner params in xml format. """
        scanner_params_xml = Element('scanner_params')

        for param_id, param in scanner_params.items():
            param_xml = SubElement(scanner_params_xml, 'scanner_param')

            for name, value in [('id', param_id), ('type', param['type'])]:
                param_xml.set(name, value)

            for name, value in [
                ('name', param['name']),
                ('description', param['description']),
                ('default', param['default']),
                ('mandatory', param['mandatory']),
            ]:
                elem = SubElement(param_xml, name)
                elem.text = str(value)

        return scanner_params_xml
