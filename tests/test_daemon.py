# -*- coding: utf-8 -*-
# Copyright (C) 2014-2020 Greenbone Networks GmbH
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


# pylint: disable=invalid-name,line-too-long,no-value-for-parameter

""" Unit Test for ospd-openvas """

import io
import logging

from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock

from ospd.vts import Vts
from ospd.protocol import OspRequest

from tests.dummydaemon import DummyDaemon
from tests.helper import assert_called_once

from ospd_openvas.daemon import OSPD_PARAMS, OpenVasVtsFilter
from ospd_openvas.openvas import Openvas

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


class TestOspdOpenvas(TestCase):
    @patch('ospd_openvas.daemon.Openvas')
    def test_set_params_from_openvas_settings(self, mock_openvas: Openvas):
        mock_openvas.get_settings.return_value = {
            'non_simult_ports': '139, 445, 3389, Services/irc',
            'plugins_folder': '/foo/bar',
        }
        w = DummyDaemon()
        w.set_params_from_openvas_settings()

        self.assertEqual(mock_openvas.get_settings.call_count, 1)
        self.assertEqual(OSPD_PARAMS, OSPD_PARAMS_OUT)
        self.assertEqual(w.scan_only_params.get('plugins_folder'), '/foo/bar')

    @patch('ospd_openvas.daemon.Openvas')
    def test_sudo_available(self, mock_openvas):
        mock_openvas.check_sudo.return_value = True

        w = DummyDaemon()
        w._sudo_available = None  # pylint: disable=protected-access
        w.sudo_available  # pylint: disable=pointless-statement

        self.assertTrue(w.sudo_available)

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
        res = w.get_custom_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt.get('custom')
        )
        self.assertEqual(len(res), len(out))

    def test_get_custom_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        custom = {'a': u"\u0006"}
        w.get_custom_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', custom=custom
        )

        assert_called_once(logging.Logger.warning)

    def test_get_severities_xml(self):
        w = DummyDaemon()

        out = (
            '<severities>'
            '<severity type="cvss_base_v2">'
            'AV:N/AC:L/Au:N/C:N/I:N/A:N'
            '</severity>'
            '</severities>'
        )
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        severities = vt.get('severities')
        res = w.get_severities_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', severities
        )

        self.assertEqual(res, out)

    def test_get_severities_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        sever = {'severity_base_vector': u"\u0006"}
        w.get_severities_vt_as_xml_str(
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
        res = w.get_params_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', params)

        self.assertEqual(len(res), len(out))

    def test_get_params_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        params = {
            '1': {
                'id': '1',
                'type': 'entry',
                'default': u'\u0006',
                'name': 'dns-fuzz.timelimit',
                'description': 'Description',
            }
        }
        w.get_params_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', params)

        assert_called_once(logging.Logger.warning)

    def test_get_refs_xml(self):
        w = DummyDaemon()

        out = '<refs><ref type="url" id="http://www.mantisbt.org/"/></refs>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        refs = vt.get('vt_refs')
        res = w.get_refs_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', refs)

        self.assertEqual(res, out)

    def test_get_dependencies_xml(self):
        w = DummyDaemon()

        out = (
            '<dependencies>'
            '<dependency vt_id="1.2.3.4"/><dependency vt_id="4.3.2.1"/>'
            '</dependencies>'
        )
        dep = ['1.2.3.4', '4.3.2.1']
        res = w.get_dependencies_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', dep
        )

        self.assertEqual(res, out)

    def test_get_dependencies_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.error = Mock()

        dep = [u"\u0006"]
        w.get_dependencies_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt_dependencies=dep
        )

        assert_called_once(logging.Logger.error)

    def test_get_ctime_xml(self):
        w = DummyDaemon()

        out = '<creation_time>1237458156</creation_time>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        ctime = vt.get('creation_time')
        res = w.get_creation_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', ctime
        )

        self.assertEqual(res, out)

    def test_get_ctime_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        ctime = u'\u0006'
        w.get_creation_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', vt_creation_time=ctime
        )

        assert_called_once(logging.Logger.warning)

    def test_get_mtime_xml(self):
        w = DummyDaemon()

        out = '<modification_time>1533906565</modification_time>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        mtime = vt.get('modification_time')
        res = w.get_modification_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', mtime
        )

        self.assertEqual(res, out)

    def test_get_mtime_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        mtime = u'\u0006'
        w.get_modification_time_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', mtime
        )

        assert_called_once(logging.Logger.warning)

    def test_get_summary_xml(self):
        w = DummyDaemon()

        out = '<summary>some summary</summary>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        summary = vt.get('summary')
        res = w.get_summary_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', summary
        )

        self.assertEqual(res, out)

    def test_get_summary_xml_failed(self):
        w = DummyDaemon()

        summary = u'\u0006'
        logging.Logger.warning = Mock()
        w.get_summary_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', summary)

        assert_called_once(logging.Logger.warning)

    def test_get_impact_xml(self):
        w = DummyDaemon()

        out = '<impact>some impact</impact>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        impact = vt.get('impact')
        res = w.get_impact_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', impact)

        self.assertEqual(res, out)

    def test_get_impact_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        impact = u'\u0006'
        w.get_impact_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', impact)

        assert_called_once(logging.Logger.warning)

    def test_get_insight_xml(self):
        w = DummyDaemon()

        out = '<insight>some insight</insight>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        insight = vt.get('insight')
        res = w.get_insight_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', insight
        )

        self.assertEqual(res, out)

    def test_get_insight_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        insight = u'\u0006'
        w.get_insight_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', insight)

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

        res = w.get_solution_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061',
            solution,
            solution_type,
            solution_method,
        )

        self.assertEqual(res, out)

    def test_get_solution_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        solution = u'\u0006'
        w.get_solution_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', solution)

        assert_called_once(logging.Logger.warning)

    def test_get_detection_xml(self):
        w = DummyDaemon()

        out = '<detection qod_type="remote_banner"/>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        detection_type = vt.get('qod_type')

        res = w.get_detection_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', qod_type=detection_type
        )

        self.assertEqual(res, out)

    def test_get_detection_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        detection = u'\u0006'
        w.get_detection_vt_as_xml_str('1.3.6.1.4.1.25623.1.0.100061', detection)

        assert_called_once(logging.Logger.warning)

    def test_get_affected_xml(self):
        w = DummyDaemon()
        out = '<affected>some affection</affected>'
        vt = w.VTS['1.3.6.1.4.1.25623.1.0.100061']
        affected = vt.get('affected')

        res = w.get_affected_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', affected=affected
        )

        self.assertEqual(res, out)

    def test_get_affected_xml_failed(self):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        affected = u"\u0006" + "affected"
        w.get_affected_vt_as_xml_str(
            '1.3.6.1.4.1.25623.1.0.100061', affected=affected
        )

        assert_called_once(logging.Logger.warning)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.OSPDopenvas.set_params_from_openvas_settings')
    def test_feed_is_outdated_none(
        self, mock_set_params: MagicMock, mock_path_exists: MagicMock
    ):
        w = DummyDaemon()

        w.scan_only_params['plugins_folder'] = '/foo/bar'

        # Return None
        mock_path_exists.return_value = False

        ret = w.feed_is_outdated('1234')
        self.assertIsNone(ret)

        self.assertEqual(mock_set_params.call_count, 1)
        self.assertEqual(mock_path_exists.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_feed_is_outdated_true(
        self, mock_path_open: MagicMock, mock_path_exists: MagicMock,
    ):
        read_data = 'PLUGIN_SET = "1235";'

        mock_path_exists.return_value = True
        mock_read = MagicMock(name='Path open context manager')
        mock_read.__enter__ = MagicMock(return_value=io.StringIO(read_data))
        mock_path_open.return_value = mock_read

        w = DummyDaemon()

        # Return True
        w.scan_only_params['plugins_folder'] = '/foo/bar'

        ret = w.feed_is_outdated('1234')
        self.assertTrue(ret)

        self.assertEqual(mock_path_exists.call_count, 1)
        self.assertEqual(mock_path_open.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_feed_is_outdated_false(
        self, mock_path_open: MagicMock, mock_path_exists: MagicMock,
    ):
        mock_path_exists.return_value = True

        read_data = 'PLUGIN_SET = "1234"'
        mock_path_exists.return_value = True
        mock_read = MagicMock(name='Path open context manager')
        mock_read.__enter__ = MagicMock(return_value=io.StringIO(read_data))
        mock_path_open.return_value = mock_read

        w = DummyDaemon()
        w.scan_only_params['plugins_folder'] = '/foo/bar'

        ret = w.feed_is_outdated('1234')
        self.assertFalse(ret)

        self.assertEqual(mock_path_exists.call_count, 1)
        self.assertEqual(mock_path_open.call_count, 1)

    def test_check_feed_cache_unavailable(self):
        w = DummyDaemon()
        w.vts.is_cache_available = False
        w.feed_is_outdated = Mock()
        res = w.check_feed()

        self.assertFalse(res)
        w.feed_is_outdated.assert_not_called()

    @patch('ospd_openvas.daemon.ScanDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_log_to_list')
    def test_get_openvas_result(self, mock_add_scan_log_to_list, MockDBClass):
        w = DummyDaemon()

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            "LOG||||||general/Host_Details||||||Host dead",
        ]
        MockDBClass.get_result.return_value = results
        mock_add_scan_log_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456', 'localhost')
        mock_add_scan_log_to_list.assert_called_with(
            host='localhost',
            hostname='',
            name='',
            port='general/Host_Details',
            qod='',
            test_id='',
            uri='',
            value='Host dead',
        )

    @patch('ospd_openvas.daemon.ScanDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_error_to_list')
    def test_get_openvas_result_host_deny(
        self, mock_add_scan_error_to_list, MockDBClass
    ):
        w = DummyDaemon()

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            "ERRMSG|||127.0.0.1|||||||||Host access denied.",
        ]
        MockDBClass.get_result.return_value = results
        mock_add_scan_error_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456', '')
        mock_add_scan_error_to_list.assert_called_with(
            host='127.0.0.1',
            hostname='127.0.0.1',
            name='',
            port='',
            test_id='',
            uri='',
            value='Host access denied.',
        )

    @patch('ospd_openvas.daemon.ScanDB')
    def test_get_openvas_result_dead_hosts(self, MockDBClass):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            "DEADHOST||| ||| ||| |||4",
        ]
        MockDBClass.get_result.return_value = results
        w.scan_collection.set_amount_dead_hosts = MagicMock()

        w.report_openvas_results(MockDBClass, '123-456', 'localhost')
        w.scan_collection.set_amount_dead_hosts.assert_called_with(
            '123-456', total_dead=4,
        )

    @patch('ospd_openvas.daemon.ScanDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_alarm_to_list')
    def test_result_without_vt_oid(
        self, mock_add_scan_alarm_to_list, MockDBClass
    ):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])
        w.scan_collection.scans_table['123-456']['results'] = list()
        results = ["ALARM||| ||| ||| |||some alarm|||path", None]
        MockDBClass.get_result.return_value = results
        mock_add_scan_alarm_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456', 'localhost')

        assert_called_once(logging.Logger.warning)

    @patch('ospd_openvas.db.KbDB')
    def test_openvas_is_alive_already_stopped(self, mock_db):
        w = DummyDaemon()
        # mock_psutil = MockPsutil.return_value
        mock_db.scan_is_stopped.return_value = True
        ret = w.is_openvas_process_alive(mock_db, '1234', 'a1-b2-c3-d4')

        self.assertTrue(ret)

    @patch('ospd_openvas.db.KbDB')
    def test_openvas_is_alive_still(self, mock_db):
        w = DummyDaemon()
        # mock_psutil = MockPsutil.return_value
        mock_db.scan_is_stopped.return_value = False
        ret = w.is_openvas_process_alive(mock_db, '1234', 'a1-b2-c3-d4')

        self.assertFalse(ret)

    @patch('ospd_openvas.daemon.OSPDaemon.set_scan_host_progress')
    def test_update_progress(self, mock_set_scan_host_progress):
        w = DummyDaemon()

        mock_set_scan_host_progress.return_value = None

        msg = '0/-1'
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)

        w.create_scan('123-456', targets, None, [])
        w.update_progress('123-456', 'localhost', msg)

        mock_set_scan_host_progress.assert_called_with(
            '123-456', host='localhost', progress=-1
        )


class TestFilters(TestCase):
    def test_format_vt_modification_time(self):
        ovformat = OpenVasVtsFilter(None)
        td = '1517443741'
        formatted = ovformat.format_vt_modification_time(td)
        self.assertEqual(formatted, "20180201000901")

    def test_get_filtered_vts_false(self):
        w = DummyDaemon()
        vts_collection = ['1234', '1.3.6.1.4.1.25623.1.0.100061']

        ovfilter = OpenVasVtsFilter(w.nvti)
        res = ovfilter.get_filtered_vts_list(
            vts_collection, "modification_time<10"
        )
        self.assertNotIn('1.3.6.1.4.1.25623.1.0.100061', res)

    def test_get_filtered_vts_true(self):
        w = DummyDaemon()
        vts_collection = ['1234', '1.3.6.1.4.1.25623.1.0.100061']

        ovfilter = OpenVasVtsFilter(w.nvti)
        res = ovfilter.get_filtered_vts_list(
            vts_collection, "modification_time>10"
        )
        self.assertIn('1.3.6.1.4.1.25623.1.0.100061', res)
