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


from unittest.mock import Mock


def assert_called_once(mock: Mock):
    if hasattr(mock, 'assert_called_once'):
        return mock.assert_called_once()

    if not mock.call_count == 1:
        msg = "Expected '%s' to have been called once. Called %s times.%s" % (
            mock._mock_name or 'mock',  # pylint: disable=protected-access
            mock.call_count,
            mock._calls_repr(),  # pylint: disable=protected-access
        )
        raise AssertionError(msg)


def assert_called(mock: Mock):
    """assert that the mock was called at least once"""
    if mock.call_count == 0:
        msg = "Expected '{}' to have been called.".format(
            mock._mock_name or 'mock'  # pylint: disable=protected-access
        )
        raise AssertionError(msg)


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
