# -*- coding: utf-8 -*-
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


# pylint: disable=invalid-name,line-too-long,no-value-for-parameter

""" Unit Test for ospd-openvas """

import io
import logging
from pathlib import Path

from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock

from ospd.protocol import OspRequest

from tests.dummydaemon import DummyDaemon
from tests.helper import assert_called_once

from ospd_openvas.daemon import (
    OSPD_PARAMS,
    OpenVasVtsFilter,
)
from ospd_openvas.openvas import Openvas
from ospd_openvas.notus import Notus, hashsum_verificator

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
    'alive_test_ports': {
        'type': 'string',
        'name': 'alive_test_ports',
        'default': '21-23,25,53,80,110-111,135,139,143,443,445,'
        + '993,995,1723,3306,3389,5900,8080',
        'mandatory': 0,
        'visible_for_client': True,
        'description': ('Port list used for host alive detection.'),
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
    'test_alive_wait_timeout': {
        'type': 'integer',
        'name': 'test_alive_wait_timeout',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'This is the default timeout to wait for replies after last '
            + 'packet was sent.'
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
    'results_per_host': {
        'type': 'integer',
        'name': 'results_per_host',
        'default': 10,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Amount of fake results generated per each host in the target '
            + 'list for a dry run scan.'
        ),
    },
    'table_driven_lsc': {
        'type': 'boolean',
        'name': 'table_driven_lsc',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'If this option is enabled a scanner for table_driven_lsc will '
            + 'scan package results.'
        ),
    },
}


class TestOspdOpenvas(TestCase):
    def test_return_disabled_verifier(self):
        verifier = hashsum_verificator(Path('/tmp'), True)
        self.assertEqual(verifier(Path('/tmp')), True)

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
        w._is_running_as_root = False  # pylint: disable=protected-access

        self.assertTrue(w.sudo_available)

    def test_update_vts(self):
        daemon = DummyDaemon()
        daemon.notus = MagicMock(spec=Notus)
        daemon.update_vts()
        self.assertEqual(daemon.notus.reload_cache.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_get_feed_info(
        self,
        mock_path_open: MagicMock,
        mock_path_exists: MagicMock,
    ):
        read_data = 'PLUGIN_SET = "1235";'

        mock_path_exists.return_value = True
        mock_read = MagicMock(name='Path open context manager')
        mock_read.__enter__ = MagicMock(return_value=io.StringIO(read_data))
        mock_path_open.return_value = mock_read

        w = DummyDaemon()

        # Return True
        w.scan_only_params['plugins_folder'] = '/foo/bar'

        ret = w.get_feed_info()
        self.assertEqual(ret, {"PLUGIN_SET": "1235"})

        self.assertEqual(mock_path_exists.call_count, 1)
        self.assertEqual(mock_path_open.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.OSPDopenvas.set_params_from_openvas_settings')
    def test_get_feed_info_none(
        self, mock_set_params: MagicMock, mock_path_exists: MagicMock
    ):
        w = DummyDaemon()

        w.scan_only_params['plugins_folder'] = '/foo/bar'

        # Return None
        mock_path_exists.return_value = False

        ret = w.get_feed_info()
        self.assertEqual(ret, {})

        self.assertEqual(mock_set_params.call_count, 1)
        self.assertEqual(mock_path_exists.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_feed_is_outdated_true(
        self,
        mock_path_open: MagicMock,
        mock_path_exists: MagicMock,
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
        self,
        mock_path_open: MagicMock,
        mock_path_exists: MagicMock,
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

        w.feed_is_outdated.assert_not_called()

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_log_to_list')
    def test_get_openvas_result(self, mock_add_scan_log_to_list, MockDBClass):
        w = DummyDaemon()

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            "LOG|||192.168.0.1|||localhost|||general/Host_Details||||||Host"
            " dead",
        ]
        MockDBClass.get_result.return_value = results
        mock_add_scan_log_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456')
        mock_add_scan_log_to_list.assert_called_with(
            host='192.168.0.1',
            hostname='localhost',
            name='',
            port='general/Host_Details',
            qod='',
            test_id='',
            uri='',
            value='Host dead',
        )

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_error_to_list')
    def test_get_openvas_result_host_deny(
        self, mock_add_scan_error_to_list, MockDBClass
    ):
        w = DummyDaemon()

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            "ERRMSG|||127.0.0.1|||localhost|||||||||Host access denied.",
        ]
        MockDBClass.get_result.return_value = results
        mock_add_scan_error_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456')
        mock_add_scan_error_to_list.assert_called_with(
            host='127.0.0.1',
            hostname='localhost',
            name='',
            port='',
            test_id='',
            uri='',
            value='Host access denied.',
        )

    @patch('ospd_openvas.daemon.BaseDB')
    def test_get_openvas_result_dead_hosts(self, MockDBClass):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            "DEADHOST||| ||| ||| ||| |||4",
        ]
        MockDBClass.get_result.return_value = results
        w.scan_collection.set_amount_dead_hosts = MagicMock()

        w.report_openvas_results(MockDBClass, '123-456')
        w.scan_collection.set_amount_dead_hosts.assert_called_with(
            '123-456',
            total_dead=4,
        )

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_log_to_list')
    def test_get_openvas_result_host_start(
        self, mock_add_scan_log_to_list, MockDBClass
    ):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            "HOST_START|||192.168.10.124||| ||| ||||||today 1",
        ]

        MockDBClass.get_result.return_value = results
        mock_add_scan_log_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456')

        mock_add_scan_log_to_list.assert_called_with(
            host='192.168.10.124',
            name='HOST_START',
            value='today 1',
        )

    @patch('ospd_openvas.daemon.BaseDB')
    def test_get_openvas_result_hosts_count(self, MockDBClass):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            "HOSTS_COUNT||| ||| ||| ||| |||4",
        ]
        MockDBClass.get_result.return_value = results
        w.set_scan_total_hosts = MagicMock()

        w.report_openvas_results(MockDBClass, '123-456')
        w.set_scan_total_hosts.assert_called_with(
            '123-456',
            4,
        )

    @patch('ospd_openvas.daemon.BaseDB')
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
        results = ["ALARM||| ||| ||| ||| |||some alarm|||path", None]
        MockDBClass.get_result.return_value = results
        mock_add_scan_alarm_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456')

        assert_called_once(logging.Logger.warning)

    @patch('psutil.Popen')
    def test_openvas_is_alive_already_stopped(self, mock_process):
        w = DummyDaemon()

        mock_process.is_running.return_value = True
        ret = w.is_openvas_process_alive(mock_process)
        self.assertTrue(ret)

    @patch('psutil.Popen')
    def test_openvas_is_alive_still(self, mock_process):
        w = DummyDaemon()

        mock_process.is_running.return_value = False
        ret = w.is_openvas_process_alive(mock_process)
        self.assertFalse(ret)

    @patch('ospd_openvas.daemon.OSPDaemon.set_scan_progress_batch')
    @patch('ospd_openvas.daemon.OSPDaemon.sort_host_finished')
    @patch('ospd_openvas.db.KbDB')
    def test_report_openvas_scan_status(
        self, mock_db, mock_sort_host_finished, mock_set_scan_progress_batch
    ):
        w = DummyDaemon()

        mock_set_scan_progress_batch.return_value = None
        mock_sort_host_finished.return_value = None
        mock_db.get_scan_status.return_value = [
            '192.168.0.1/15/1000',
            '192.168.0.2/15/0',
            '192.168.0.3/15/-1',
            '192.168.0.4/1500/1500',
        ]

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)

        w.create_scan('123-456', targets, None, [])
        w.report_openvas_scan_status(mock_db, '123-456')

        mock_set_scan_progress_batch.assert_called_with(
            '123-456',
            host_progress={
                '192.168.0.1': 1,
                '192.168.0.3': -1,
                '192.168.0.4': 100,
            },
        )

        mock_sort_host_finished.assert_called_with(
            '123-456', ['192.168.0.3', '192.168.0.4']
        )


class TestFilters(TestCase):
    def test_format_vt_modification_time(self):
        ovformat = OpenVasVtsFilter(None, None)
        td = '1517443741'
        formatted = ovformat.format_vt_modification_time(td)
        self.assertEqual(formatted, "20180201000901")

    def test_get_filtered_vts_false(self):
        w = DummyDaemon()
        vts_collection = ['1234', '1.3.6.1.4.1.25623.1.0.100061']

        ovfilter = OpenVasVtsFilter(w.nvti, None)
        res = ovfilter.get_filtered_vts_list(
            vts_collection, "modification_time<10"
        )
        self.assertNotIn('1.3.6.1.4.1.25623.1.0.100061', res)

    def test_get_filtered_vts_true(self):
        w = DummyDaemon()
        vts_collection = ['1234', '1.3.6.1.4.1.25623.1.0.100061']

        ovfilter = OpenVasVtsFilter(w.nvti, None)
        res = ovfilter.get_filtered_vts_list(
            vts_collection, "modification_time>10"
        )
        self.assertIn('1.3.6.1.4.1.25623.1.0.100061', res)
