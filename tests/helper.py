# -*- coding: utf-8 -*-
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
# pylint: disable=protected-access

import time

from unittest.mock import Mock

from xml.etree import ElementTree as et

from ospd.ospd import OSPDaemon


def assert_called_once(mock: Mock):
    if hasattr(mock, 'assert_called_once'):
        return mock.assert_called_once()

    if not mock.call_count == 1:
        # pylint: disable=protected-access
        msg = (
            f"Expected '{mock._mock_name or 'mock'}' to have "
            f"been called once. Called {mock.call_count} "
            f"times.{mock._calls_repr()}"
        )
        raise AssertionError(msg)


def assert_called(mock: Mock):
    """assert that the mock was called at least once"""
    if mock.call_count == 0:
        # pylint: disable=protected-access
        msg = f"Expected '{mock._mock_name or 'mock'}' to have been called."
        raise AssertionError(msg)


class FakePsutil:
    def __init__(self, available=None):
        self.available = available


class FakeStream:
    def __init__(self, return_value=True):
        self.response = b''
        self.return_value = return_value

    def write(self, data):
        self.response = self.response + data
        return self.return_value

    def get_response(self):
        return et.fromstring(self.response)


class FakeDataManager:
    def __init__(self):
        pass

    def dict(self):
        return dict()


class DummyWrapper(OSPDaemon):
    def __init__(self, results, checkresult=True):
        super().__init__()
        self.checkresult = checkresult
        self.results = results
        self.initialized = True
        self.scan_collection.data_manager = FakeDataManager()
        self.scan_collection.file_storage_dir = '/tmp'

    def check(self):
        return self.checkresult

    @staticmethod
    def get_custom_vt_as_xml_str(vt_id, custom):
        return '<custom><mytest>static test</mytest></custom>'

    @staticmethod
    def get_params_vt_as_xml_str(vt_id, vt_params):
        return (
            '<params><param id="abc" type="string">'
            '<name>ABC</name><description>Test ABC</description>'
            '<default>yes</default></param>'
            '<param id="def" type="string">'
            '<name>DEF</name><description>Test DEF</description>'
            '<default>no</default></param></params>'
        )

    @staticmethod
    def get_refs_vt_as_xml_str(vt_id, vt_refs):
        response = (
            '<refs><ref type="cve" id="CVE-2010-4480"/>'
            '<ref type="url" id="http://example.com"/></refs>'
        )
        return response

    @staticmethod
    def get_dependencies_vt_as_xml_str(vt_id, vt_dependencies):
        response = (
            '<dependencies>'
            '<dependency vt_id="1.3.6.1.4.1.25623.1.0.50282" />'
            '<dependency vt_id="1.3.6.1.4.1.25623.1.0.50283" />'
            '</dependencies>'
        )

        return response

    @staticmethod
    def get_severities_vt_as_xml_str(vt_id, severities):
        response = (
            '<severities><severity cvss_base="5.0" cvss_'
            'type="cvss_base_v2">AV:N/AC:L/Au:N/C:N/I:N/'
            'A:P</severity></severities>'
        )

        return response

    @staticmethod
    def get_detection_vt_as_xml_str(
        vt_id, detection=None, qod_type=None, qod=None
    ):
        response = '<detection qod_type="package">some detection</detection>'

        return response

    @staticmethod
    def get_summary_vt_as_xml_str(vt_id, summary):
        response = '<summary>Some summary</summary>'

        return response

    @staticmethod
    def get_affected_vt_as_xml_str(vt_id, affected):
        response = '<affected>Some affected</affected>'

        return response

    @staticmethod
    def get_impact_vt_as_xml_str(vt_id, impact):
        response = '<impact>Some impact</impact>'

        return response

    @staticmethod
    def get_insight_vt_as_xml_str(vt_id, insight):
        response = '<insight>Some insight</insight>'

        return response

    @staticmethod
    def get_solution_vt_as_xml_str(
        vt_id, solution, solution_type=None, solution_method=None
    ):
        response = '<solution>Some solution</solution>'

        return response

    @staticmethod
    def get_creation_time_vt_as_xml_str(
        vt_id, creation_time
    ):  # pylint: disable=arguments-differ, arguments-renamed
        response = '<creation_time>%s</creation_time>' % creation_time

        return response

    @staticmethod
    def get_modification_time_vt_as_xml_str(
        vt_id, modification_time
    ):  # pylint: disable=arguments-differ, arguments-renamed
        response = (
            '<modification_time>%s</modification_time>' % modification_time
        )

        return response

    def exec_scan(self, scan_id):
        time.sleep(0.01)
        for res in self.results:
            if res.result_type == 'log':
                self.add_scan_log(
                    scan_id,
                    res.host,
                    res.hostname,
                    res.name,
                    res.value,
                    res.port,
                )
            if res.result_type == 'error':
                self.add_scan_error(
                    scan_id,
                    res.host,
                    res.hostname,
                    res.name,
                    res.value,
                    res.port,
                )
            elif res.result_type == 'host-detail':
                self.add_scan_host_detail(
                    scan_id, res.host, res.hostname, res.name, res.value
                )
            elif res.result_type == 'alarm':
                self.add_scan_alarm(
                    scan_id,
                    res.host,
                    res.hostname,
                    res.name,
                    res.value,
                    res.port,
                    res.test_id,
                    res.severity,
                    res.qod,
                )
            else:
                raise ValueError(res.result_type)


OSPD_PARAMS_OUT = {
    'auto_enable_dependencies': {
        'type': 'boolean',
        'name': 'auto_enable_dependencies',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': 'Automatically enable the plugins that are depended on',
    },
    'cgi_path': {
        'type': 'string',
        'name': 'cgi_path',
        'default': '/cgi-bin:/scripts',
        'mandatory': 1,
        'visible_for_client': True,
        'description': 'Look for default CGIs in /cgi-bin and /scripts',
    },
    'checks_read_timeout': {
        'type': 'integer',
        'name': 'checks_read_timeout',
        'default': 5,
        'mandatory': 1,
        'visible_for_client': True,
        'description': (
            'Number  of seconds that the security checks will '
            + 'wait for when doing a recv()'
        ),
    },
    'non_simult_ports': {
        'type': 'string',
        'name': 'non_simult_ports',
        'default': '139, 445, 3389, Services/irc',
        'mandatory': 1,
        'visible_for_client': True,
        'description': (
            'Prevent to make two connections on the same given '
            + 'ports at the same time.'
        ),
    },
    'open_sock_max_attempts': {
        'type': 'integer',
        'name': 'open_sock_max_attempts',
        'default': 5,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Number of unsuccessful retries to open the socket '
            + 'before to set the port as closed.'
        ),
    },
    'timeout_retry': {
        'type': 'integer',
        'name': 'timeout_retry',
        'default': 5,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Number of retries when a socket connection attempt ' + 'timesout.'
        ),
    },
    'optimize_test': {
        'type': 'boolean',
        'name': 'optimize_test',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'By default, optimize_test is enabled which means openvas does '
            + 'trust the remote host banners and is only launching plugins '
            + 'against the services they have been designed to check. '
            + 'For example it will check a web server claiming to be IIS only '
            + 'for IIS related flaws but will skip plugins testing for Apache '
            + 'flaws, and so on. This default behavior is used to optimize '
            + 'the scanning performance and to avoid false positives. '
            + 'If you are not sure that the banners of the remote host '
            + 'have been tampered with, you can disable this option.'
        ),
    },
    'plugins_timeout': {
        'type': 'integer',
        'name': 'plugins_timeout',
        'default': 5,
        'mandatory': 0,
        'visible_for_client': True,
        'description': 'This is the maximum lifetime, in seconds of a plugin.',
    },
    'report_host_details': {
        'type': 'boolean',
        'name': 'report_host_details',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': '',
    },
    'safe_checks': {
        'type': 'boolean',
        'name': 'safe_checks',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': (
            'Disable the plugins with potential to crash '
            + 'the remote services'
        ),
    },
    'scanner_plugins_timeout': {
        'type': 'integer',
        'name': 'scanner_plugins_timeout',
        'default': 36000,
        'mandatory': 1,
        'visible_for_client': True,
        'description': 'Like plugins_timeout, but for ACT_SCANNER plugins.',
    },
    'time_between_request': {
        'type': 'integer',
        'name': 'time_between_request',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Allow to set a wait time between two actions '
            + '(open, send, close).'
        ),
    },
    'unscanned_closed': {
        'type': 'boolean',
        'name': 'unscanned_closed',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': '',
    },
    'unscanned_closed_udp': {
        'type': 'boolean',
        'name': 'unscanned_closed_udp',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': '',
    },
    'expand_vhosts': {
        'type': 'boolean',
        'name': 'expand_vhosts',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': 'Whether to expand the target hosts '
        + 'list of vhosts with values gathered from sources '
        + 'such as reverse-lookup queries and VT checks '
        + 'for SSL/TLS certificates.',
    },
    'test_empty_vhost': {
        'type': 'boolean',
        'name': 'test_empty_vhost',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': True,
        'description': 'If  set  to  yes, the scanner will '
        + 'also test the target by using empty vhost value '
        + 'in addition to the targets associated vhost values.',
    },
    'max_hosts': {
        'type': 'integer',
        'name': 'max_hosts',
        'default': 30,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'The maximum number of hosts to test at the same time which '
            + 'should be given to the client (which can override it). '
            + 'This value must be computed given your bandwidth, '
            + 'the number of hosts you want to test, your amount of '
            + 'memory and the performance of your processor(s).'
        ),
    },
    'max_checks': {
        'type': 'integer',
        'name': 'max_checks',
        'default': 10,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'The number of plugins that will run against each host being '
            + 'tested. Note that the total number of process will be max '
            + 'checks x max_hosts so you need to find a balance between '
            + 'these two options. Note that launching too many plugins at '
            + 'the same time may disable the remote host, either temporarily '
            + '(ie: inetd closes its ports) or definitely (the remote host '
            + 'crash because it is asked to do too many things at the '
            + 'same time), so be careful.'
        ),
    },
    'port_range': {
        'type': 'string',
        'name': 'port_range',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'This is the default range of ports that the scanner plugins will '
            + 'probe. The syntax of this option is flexible, it can be a '
            + 'single range ("1-1500"), several ports ("21,23,80"), several '
            + 'ranges of ports ("1-1500,32000-33000"). Note that you can '
            + 'specify UDP and TCP ports by prefixing each range by T or U. '
            + 'For instance, the following range will make openvas scan UDP '
            + 'ports 1 to 1024 and TCP ports 1 to 65535 : '
            + '"T:1-65535,U:1-1024".'
        ),
    },
    'test_alive_hosts_only': {
        'type': 'boolean',
        'name': 'test_alive_hosts_only',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'If this option is set, openvas will scan the target list for '
            + 'alive hosts in a separate process while only testing those '
            + 'hosts which are identified as alive. This boosts the scan '
            + 'speed of target ranges with a high amount of dead hosts '
            + 'significantly.'
        ),
    },
    'source_iface': {
        'type': 'string',
        'name': 'source_iface',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Name of the network interface that will be used as the source '
            + 'of connections established by openvas. The scan won\'t be '
            + 'launched if the value isn\'t authorized according to '
            + '(sys_)ifaces_allow / (sys_)ifaces_deny if present.'
        ),
    },
    'ifaces_allow': {
        'type': 'string',
        'name': 'ifaces_allow',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of interfaces names that are authorized '
            + 'as source_iface values.'
        ),
    },
    'ifaces_deny': {
        'type': 'string',
        'name': 'ifaces_deny',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of interfaces names that are not '
            + 'authorized as source_iface values.'
        ),
    },
    'hosts_allow': {
        'type': 'string',
        'name': 'hosts_allow',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of the only targets that are authorized '
            + 'to be scanned. Supports the same syntax as the list targets. '
            + 'Both target hostnames and the address to which they resolve '
            + 'are checked. Hostnames in hosts_allow list are not resolved '
            + 'however.'
        ),
    },
    'hosts_deny': {
        'type': 'string',
        'name': 'hosts_deny',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of targets that are not authorized to '
            + 'be scanned. Supports the same syntax as the list targets. '
            + 'Both target hostnames and the address to which they resolve '
            + 'are checked. Hostnames in hosts_deny list are not '
            + 'resolved however.'
        ),
    },
}
