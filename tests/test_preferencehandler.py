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


import logging

from unittest import TestCase
from unittest.mock import call, patch, Mock, MagicMock

from ospd.vts import Vts

from tests.dummydaemon import DummyDaemon
from tests.helper import assert_called_once

import ospd_openvas.db

from ospd_openvas.openvas import Openvas
from ospd_openvas.preferencehandler import (
    AliveTest,
    BOREAS_SETTING_NAME,
    BOREAS_ALIVE_TEST,
    PreferenceHandler,
)


class PreferenceHandlerTestCase(TestCase):
    @patch('ospd_openvas.db.KbDB')
    def test_process_vts_not_found(self, mock_kb):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100065': {'3': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, w.nvti)
        w.nvti.get_nvt_metadata.return_value = None
        p._process_vts(vts)

        assert_called_once(logging.Logger.warning)

    def test_process_vts_bad_param_id(self):
        w = DummyDaemon()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100061': {'3': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }

        p = PreferenceHandler('1234-1234', None, w.scan_collection, w.nvti)

        ret = p._process_vts(vts)

        self.assertFalse(ret[1])

    def test_process_vts(self):
        w = DummyDaemon()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100061': {'1': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }
        vt_out = (
            ['1.3.6.1.4.1.25623.1.0.100061'],
            {'1.3.6.1.4.1.25623.1.0.100061:1:entry:Data length :': 'new value'},
        )

        p = PreferenceHandler('1234-1234', None, w.scan_collection, w.nvti)
        ret = p._process_vts(vts)

        self.assertEqual(ret, vt_out)

    @patch('ospd_openvas.db.KbDB')
    def test_set_plugins_false(self, mock_kb):
        w = DummyDaemon()

        w.scan_collection.get_vts = Mock()
        w.scan_collection.get_vts.return_value = {}

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, w.nvti)
        p.kbdb.add_scan_preferences = Mock()
        r = p.prepare_plugins_for_openvas()

        self.assertFalse(r)

    @patch('ospd_openvas.db.KbDB')
    def test_set_plugins_true(self, mock_kb):
        w = DummyDaemon()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100061': {'3': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }

        w.scan_collection.get_vts = Mock()
        w.scan_collection.get_vts.return_value = vts

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, w.nvti)
        p.kbdb.add_scan_preferences = Mock()
        r = p.prepare_plugins_for_openvas()

        self.assertTrue(r)

    def test_build_credentials_ssh_up(self):
        w = DummyDaemon()

        cred_out = [
            'auth_port_ssh|||22',
            '1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login name:|||username',
            '1.3.6.1.4.1.25623.1.0.103591:3:password:SSH password (unsafe!):|||pass',
        ]
        cred_dict = {
            'ssh': {
                'type': 'up',
                'port': '22',
                'username': 'username',
                'password': 'pass',
            }
        }
        p = PreferenceHandler('1234-1234', None, w.scan_collection, None)

        ret = p.build_credentials_as_prefs(cred_dict)

        self.assertEqual(ret, cred_out)

    def test_build_credentials(self):
        w = DummyDaemon()

        cred_out = [
            '1.3.6.1.4.1.25623.1.0.105058:1:entry:ESXi login name:|||username',
            '1.3.6.1.4.1.25623.1.0.105058:2:password:ESXi login password:|||pass',
            'auth_port_ssh|||22',
            '1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login name:|||username',
            '1.3.6.1.4.1.25623.1.0.103591:2:password:SSH key passphrase:|||pass',
            '1.3.6.1.4.1.25623.1.0.103591:4:file:SSH private key:|||',
            '1.3.6.1.4.1.25623.1.0.90023:1:entry:SMB login:|||username',
            '1.3.6.1.4.1.25623.1.0.90023:2:password]:SMB password :|||pass',
            '1.3.6.1.4.1.25623.1.0.105076:1:password:SNMP Community:some comunity',
            '1.3.6.1.4.1.25623.1.0.105076:2:entry:SNMPv3 Username:username',
            '1.3.6.1.4.1.25623.1.0.105076:3:password:SNMPv3 Password:pass',
            '1.3.6.1.4.1.25623.1.0.105076:4:radio:SNMPv3 Authentication Algorithm:some auth algo',
            '1.3.6.1.4.1.25623.1.0.105076:5:password:SNMPv3 Privacy Password:privacy pass',
            '1.3.6.1.4.1.25623.1.0.105076:6:radio:SNMPv3 Privacy Algorithm:privacy algo',
        ]
        cred_dict = {
            'ssh': {
                'type': 'ssh',
                'port': '22',
                'username': 'username',
                'password': 'pass',
            },
            'smb': {'type': 'smb', 'username': 'username', 'password': 'pass'},
            'esxi': {
                'type': 'esxi',
                'username': 'username',
                'password': 'pass',
            },
            'snmp': {
                'type': 'snmp',
                'username': 'username',
                'password': 'pass',
                'community': 'some comunity',
                'auth_algorithm': 'some auth algo',
                'privacy_password': 'privacy pass',
                'privacy_algorithm': 'privacy algo',
            },
        }

        p = PreferenceHandler('1234-1234', None, w.scan_collection, None)
        ret = p.build_credentials_as_prefs(cred_dict)

        self.assertEqual(len(ret), len(cred_out))
        self.assertIn('auth_port_ssh|||22', cred_out)
        self.assertIn(
            '1.3.6.1.4.1.25623.1.0.90023:1:entry:SMB login:|||username',
            cred_out,
        )

    def test_build_alive_test_opt_empty(self):
        w = DummyDaemon()

        target_options_dict = {'alive_test': '0'}

        p = PreferenceHandler('1234-1234', None, w.scan_collection, None)
        ret = p.build_alive_test_opt_as_prefs(target_options_dict)

        self.assertEqual(ret, [])

    def test_build_alive_test_opt(self):
        w = DummyDaemon()

        alive_test_out = [
            "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:2:checkbox:TCP ping tries also TCP-SYN ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:7:checkbox:TCP ping tries only TCP-SYN ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:3:checkbox:Do an ICMP ping|||yes",
            "1.3.6.1.4.1.25623.1.0.100315:4:checkbox:Use ARP|||no",
            "1.3.6.1.4.1.25623.1.0.100315:5:checkbox:Mark unrechable Hosts as dead (not scanning)|||yes",
        ]
        target_options_dict = {'alive_test': '2'}
        p = PreferenceHandler('1234-1234', None, w.scan_collection, None)
        ret = p.build_alive_test_opt_as_prefs(target_options_dict)

        self.assertEqual(ret, alive_test_out)

    def test_build_alive_test_opt_fail_1(self):
        w = DummyDaemon()
        logging.Logger.debug = Mock()

        target_options_dict = {'alive_test': 'a'}
        p = PreferenceHandler('1234-1234', None, w.scan_collection, None)
        target_options = p.build_alive_test_opt_as_prefs(target_options_dict)

        assert_called_once(logging.Logger.debug)
        self.assertEqual(len(target_options), 0)

    @patch('ospd_openvas.db.KbDB')
    def test_set_target(self, mock_kb):
        w = DummyDaemon()

        w.scan_collection.get_host_list = MagicMock(return_value='192.168.0.1')

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        p.prepare_target_for_openvas()

        p.kbdb.add_scan_preferences.assert_called_with(
            p._openvas_scan_id, ['TARGET|||192.168.0.1'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_ports(self, mock_kb):
        w = DummyDaemon()

        w.scan_collection.get_ports = MagicMock(return_value='80,443')

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        p.prepare_ports_for_openvas()

        p.kbdb.add_scan_preferences.assert_called_with(
            p._openvas_scan_id, ['port_range|||80,443'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_main_kbindex(self, mock_kb):
        w = DummyDaemon()

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p.kbdb.add_scan_preferences = Mock()
        p.kbdb.index = 2
        p.prepare_main_kbindex_for_openvas()

        p.kbdb.add_scan_preferences.assert_called_with(
            p._openvas_scan_id, ['ov_maindbid|||2'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_credentials(self, mock_kb):
        w = DummyDaemon()

        creds = {
            'ssh': {
                'type': 'ssh',
                'port': '22',
                'username': 'username',
                'password': 'pass',
            },
            'smb': {'type': 'smb', 'username': 'username', 'password': 'pass'},
            'esxi': {
                'type': 'esxi',
                'username': 'username',
                'password': 'pass',
            },
            'snmp': {
                'type': 'snmp',
                'username': 'username',
                'password': 'pass',
                'community': 'some comunity',
                'auth_algorithm': 'some auth algo',
                'privacy_password': 'privacy pass',
                'privacy_algorithm': 'privacy algo',
            },
        }

        w.scan_collection.get_credentials = MagicMock(return_value=creds)

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        r = p.prepare_credentials_for_openvas()

        self.assertTrue(r)
        assert_called_once(p.kbdb.add_scan_preferences)

    @patch('ospd_openvas.db.KbDB')
    def test_set_credentials(self, mock_kb):
        w = DummyDaemon()

        # bad cred type shh instead of ssh
        creds = {
            'shh': {
                'type': 'ssh',
                'port': '22',
                'username': 'username',
                'password': 'pass',
            },
        }

        w.scan_collection.get_credentials = MagicMock(return_value=creds)

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        r = p.prepare_credentials_for_openvas()

        self.assertFalse(r)

    @patch('ospd_openvas.db.KbDB')
    def test_set_credentials_empty(self, mock_kb):
        w = DummyDaemon()

        creds = {}

        w.scan_collection.get_credentials = MagicMock(return_value=creds)

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        r = p.prepare_credentials_for_openvas()

        self.assertTrue(r)

    @patch('ospd_openvas.db.KbDB')
    def test_set_host_options(self, mock_kb):
        w = DummyDaemon()

        exc = '192.168.0.1'

        w.scan_collection.get_exclude_hosts = MagicMock(return_value=exc)

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        p.prepare_host_options_for_openvas()

        p.kbdb.add_scan_preferences.assert_called_with(
            p._openvas_scan_id, ['exclude_hosts|||192.168.0.1'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_host_options_none(self, mock_kb):
        w = DummyDaemon()

        exc = ''

        w.scan_collection.get_exclude_hosts = MagicMock(return_value=exc)

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        p.prepare_host_options_for_openvas()

        p.kbdb.add_scan_preferences.assert_not_called()

    @patch('ospd_openvas.db.KbDB')
    def test_set_scan_params(self, mock_kb):
        w = DummyDaemon()

        OSPD_PARAMS_MOCK = {
            'drop_privileges': {
                'type': 'boolean',
                'name': 'drop_privileges',
                'default': 0,
                'mandatory': 1,
                'description': '',
            },
        }

        opt = {'drop_privileges': 1}

        w.scan_collection.get_options = MagicMock(return_value=opt)

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        p.prepare_scan_params_for_openvas(OSPD_PARAMS_MOCK)

        p.kbdb.add_scan_preferences.assert_called_with(
            p._openvas_scan_id, ['drop_privileges|||yes']
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_reverse_lookup_opt(self, mock_kb):
        w = DummyDaemon()

        t_opt = {'reverse_lookup_only': 1}
        w.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        p.prepare_reverse_lookup_opt_for_openvas()

        p.kbdb.add_scan_preferences.assert_called_with(
            p._openvas_scan_id,
            ['reverse_lookup_only|||yes', 'reverse_lookup_unify|||no',],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_boreas_alive_test_with_settings(self, mock_kb):
        # No Boreas config setting (BOREAS_SETTING_NAME) set
        w = DummyDaemon()
        ov_setting = {'not_the_correct_setting': 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
            p._openvas_scan_id = '456-789'
            p.kbdb.add_scan_preferences = MagicMock()
            p.prepare_boreas_alive_test()

            p.kbdb.add_scan_preferences.assert_not_called()

        # Boreas config setting set but invalid alive_test.
        w = DummyDaemon()
        t_opt = {'alive_test': "error"}
        w.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
            p._openvas_scan_id = '456-789'
            p.kbdb.add_scan_preferences = MagicMock()
            p.prepare_boreas_alive_test()

            p.kbdb.add_scan_preferences.assert_not_called()

        # ALIVE_TEST_TCP_SYN_SERVICE as alive test.
        w = DummyDaemon()
        t_opt = {'alive_test': AliveTest.ALIVE_TEST_TCP_SYN_SERVICE}
        w.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
            p._openvas_scan_id = '456-789'
            p.kbdb.add_scan_preferences = MagicMock()
            p.prepare_boreas_alive_test()

            calls = [call(p._openvas_scan_id, [BOREAS_ALIVE_TEST + '|||16'])]
            p.kbdb.add_scan_preferences.assert_has_calls(calls)

        # ICMP was chosen as alive test.
        w = DummyDaemon()
        t_opt = {'alive_test': AliveTest.ALIVE_TEST_ICMP}
        w.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
            p._openvas_scan_id = '456-789'
            p.kbdb.add_scan_preferences = MagicMock()
            p.prepare_boreas_alive_test()

            calls = [call(p._openvas_scan_id, [BOREAS_ALIVE_TEST + '|||2'])]
            p.kbdb.add_scan_preferences.assert_has_calls(calls)

        # "Scan Config Default" as alive_test.
        w = DummyDaemon()
        t_opt = {'alive_test': AliveTest.ALIVE_TEST_SCAN_CONFIG_DEFAULT}
        w.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
            p._openvas_scan_id = '456-789'
            p.kbdb.add_scan_preferences = MagicMock()
            p.prepare_boreas_alive_test()

            calls = [call(p._openvas_scan_id, [BOREAS_ALIVE_TEST + '|||2'])]
            p.kbdb.add_scan_preferences.assert_has_calls(calls)

    @patch('ospd_openvas.db.KbDB')
    def test_set_boreas_alive_test_without_settings(self, mock_kb):
        w = DummyDaemon()
        t_opt = {'alive_test': 16}
        w.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
            p._openvas_scan_id = '456-789'
            p.kbdb.add_scan_preferences = MagicMock()
            p.prepare_boreas_alive_test()

            p.kbdb.add_scan_preferences.assert_not_called()

    @patch('ospd_openvas.db.KbDB')
    def test_set_alive_no_setting(self, mock_kb):
        w = DummyDaemon()

        t_opt = {}
        w.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        ov_setting = {}

        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)
            p._openvas_scan_id = '456-789'
            p.kbdb.add_scan_preferences = MagicMock()
            p.prepare_alive_test_option_for_openvas()

            p.kbdb.add_scan_preferences.assert_not_called()

    @patch('ospd_openvas.db.KbDB')
    def test_set_alive_pinghost(self, mock_kb):
        w = DummyDaemon()

        alive_test_out = [
            "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:2:checkbox:TCP ping tries also TCP-SYN ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:7:checkbox:TCP ping tries only TCP-SYN ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:3:checkbox:Do an ICMP ping|||yes",
            "1.3.6.1.4.1.25623.1.0.100315:4:checkbox:Use ARP|||no",
            "1.3.6.1.4.1.25623.1.0.100315:5:checkbox:Mark unrechable Hosts as dead (not scanning)|||yes",
        ]

        t_opt = {'alive_test': 2}
        w.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        ov_setting = {'some_setting': 1}

        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection, None)

            p._openvas_scan_id = '456-789'
            p.kbdb.add_scan_preferences = MagicMock()
            p.prepare_alive_test_option_for_openvas()

            p.kbdb.add_scan_preferences.assert_called_with(
                p._openvas_scan_id, alive_test_out,
            )
