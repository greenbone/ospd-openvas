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

# pylint: disable = too-many-lines

import logging

from unittest import TestCase
from unittest.mock import call, patch, Mock, MagicMock

from tests.dummydaemon import DummyDaemon
from tests.helper import assert_called_once

from ospd_openvas.openvas import Openvas
from ospd_openvas.preferencehandler import (
    AliveTest,
    BOREAS_SETTING_NAME,
    BOREAS_ALIVE_TEST,
    BOREAS_ALIVE_TEST_PORTS,
    PreferenceHandler,
    alive_test_methods_to_bit_field,
)


class PreferenceHandlerTestCase(TestCase):
    @patch('ospd_openvas.db.KbDB')
    def test_process_vts_not_found(self, mock_kb):
        dummy = DummyDaemon()
        logging.Logger.warning = Mock()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100065': {'3': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, dummy.nvti
        )
        dummy.nvti.get_nvt_metadata.return_value = None
        p_handler._process_vts(vts)  # pylint: disable = protected-access

        assert_called_once(logging.Logger.warning)

    def test_process_vts_bad_param_id(self):
        dummy = DummyDaemon()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100061': {'3': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }

        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, dummy.nvti
        )

        ret = p_handler._process_vts(vts)  # pylint: disable = protected-access

        self.assertFalse(ret[1])

    def test_process_vts(self):
        dummy = DummyDaemon()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100061': {'1': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }
        vt_out = (
            ['1.3.6.1.4.1.25623.1.0.100061'],
            {'1.3.6.1.4.1.25623.1.0.100061:1:entry:Data length :': 'new value'},
        )

        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, dummy.nvti
        )
        ret = p_handler._process_vts(vts)  # pylint: disable = protected-access

        self.assertEqual(ret, vt_out)

    @patch('ospd_openvas.db.KbDB')
    def test_set_plugins_false(self, mock_kb):
        dummy = DummyDaemon()

        dummy.scan_collection.get_vts = Mock()
        dummy.scan_collection.get_vts.return_value = {}

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, dummy.nvti
        )
        p_handler.kbdb.add_scan_preferences = Mock()
        ret = p_handler.prepare_plugins_for_openvas()

        self.assertFalse(ret)

    @patch('ospd_openvas.db.KbDB')
    def test_set_plugins_true(self, mock_kb):
        dummy = DummyDaemon()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100061': {'3': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }

        dummy.scan_collection.get_vts = Mock()
        dummy.scan_collection.get_vts.return_value = vts

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, dummy.nvti
        )
        p_handler.kbdb.add_scan_preferences = Mock()
        ret = p_handler.prepare_plugins_for_openvas()

        self.assertTrue(ret)

    def test_build_credentials_ssh_up(self):
        dummy = DummyDaemon()

        cred_out = [
            'auth_port_ssh|||22',
            '1.3.6.1.4.1.25623.1.0.103591:7:'
            'entry:SSH privilege login name:|||test',
            '1.3.6.1.4.1.25623.1.0.103591:8:'
            'password:SSH privilege password:|||1234',
            '1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login name:|||username',
            '1.3.6.1.4.1.25623.1.0.103591:3:'
            'password:SSH password (unsafe!):|||pass',
        ]
        cred_dict = {
            'ssh': {
                'type': 'up',
                'port': '22',
                'username': 'username',
                'password': 'pass',
                'priv_username': 'test',
                'priv_password': '1234',
            }
        }
        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, None
        )

        ret = p_handler.build_credentials_as_prefs(cred_dict)

        self.assertEqual(ret, cred_out)

    def test_build_credentials(self):
        dummy = DummyDaemon()

        cred_out = [
            '1.3.6.1.4.1.25623.1.0.105058:1:entry:ESXi login name:|||username',
            '1.3.6.1.4.1.25623.1.0.105058:2:password:'
            'ESXi login password:|||pass',
            'auth_port_ssh|||22',
            '1.3.6.1.4.1.25623.1.0.103591:1:entry:SSH login name:|||username',
            '1.3.6.1.4.1.25623.1.0.103591:2:'
            'password:SSH key passphrase:|||pass',
            '1.3.6.1.4.1.25623.1.0.103591:4:file:SSH private key:|||',
            '1.3.6.1.4.1.25623.1.0.90023:1:entry:SMB login:|||username',
            '1.3.6.1.4.1.25623.1.0.90023:2:password]:SMB password :|||pass',
            '1.3.6.1.4.1.25623.1.0.105076:1:'
            'password:SNMP Community:some comunity',
            '1.3.6.1.4.1.25623.1.0.105076:2:entry:SNMPv3 Username:username',
            '1.3.6.1.4.1.25623.1.0.105076:3:password:SNMPv3 Password:pass',
            '1.3.6.1.4.1.25623.1.0.105076:4:'
            'radio:SNMPv3 Authentication Algorithm:some auth algo',
            '1.3.6.1.4.1.25623.1.0.105076:5:'
            'password:SNMPv3 Privacy Password:privacy pass',
            '1.3.6.1.4.1.25623.1.0.105076:6:'
            'radio:SNMPv3 Privacy Algorithm:privacy algo',
            '1.3.6.1.4.1.25623.1.0.105076:7:'
            'entry:SSH privilege login name:|||test',
            '1.3.6.1.4.1.25623.1.0.105076:8:'
            'password:SSH privilege password:|||1234',
        ]
        cred_dict = {
            'ssh': {
                'type': 'ssh',
                'port': '22',
                'username': 'username',
                'password': 'pass',
                'priv_username': 'test',
                'priv_password': '1234',
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

        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, None
        )
        ret = p_handler.build_credentials_as_prefs(cred_dict)

        self.assertEqual(len(ret), len(cred_out))
        self.assertIn('auth_port_ssh|||22', cred_out)
        self.assertIn(
            '1.3.6.1.4.1.25623.1.0.90023:1:entry:SMB login:|||username',
            cred_out,
        )

    def test_build_alive_test_opt_empty(self):
        dummy = DummyDaemon()

        target_options_dict = {'alive_test': '0'}

        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, None
        )
        ret = p_handler.build_alive_test_opt_as_prefs(target_options_dict)

        self.assertEqual(ret, {})

        # alive test was supplied via separate xml element
        dummy = DummyDaemon()
        target_options_dict = {'alive_test_methods': '1', 'icmp': '0'}
        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, None
        )
        ret = p_handler.build_alive_test_opt_as_prefs(target_options_dict)
        self.assertEqual(ret, {})

    def test_build_alive_test_opt(self):
        dummy = DummyDaemon()

        alive_test_out = {
            "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping": "no",
            "1.3.6.1.4.1.25623.1.0.100315:2:checkbox:"
            "TCP ping tries also TCP-SYN ping": "no",
            "1.3.6.1.4.1.25623.1.0.100315:7:checkbox:"
            "TCP ping tries only TCP-SYN ping": "no",
            "1.3.6.1.4.1.25623.1.0.100315:3:checkbox:Do an ICMP ping": "yes",
            "1.3.6.1.4.1.25623.1.0.100315:4:checkbox:Use ARP": "no",
            (
                "1.3.6.1.4.1.25623.1.0.100315:5:checkbox:"
                "Mark unrechable Hosts as dead (not scanning)"
            ): "yes",
        }

        target_options_dict = {'alive_test': '2'}
        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, None
        )
        ret = p_handler.build_alive_test_opt_as_prefs(target_options_dict)

        self.assertEqual(ret, alive_test_out)

        # alive test was supplied via sepertae xml element
        dummy = DummyDaemon()
        target_options_dict = {'alive_test_methods': '1', 'icmp': '1'}
        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, None
        )
        ret = p_handler.build_alive_test_opt_as_prefs(target_options_dict)
        self.assertEqual(ret, alive_test_out)

    def test_build_alive_test_opt_fail_1(self):
        dummy = DummyDaemon()
        logging.Logger.debug = Mock()

        target_options_dict = {'alive_test': 'a'}
        p_handler = PreferenceHandler(
            '1234-1234', None, dummy.scan_collection, None
        )
        target_options = p_handler.build_alive_test_opt_as_prefs(
            target_options_dict
        )

        assert_called_once(logging.Logger.debug)
        self.assertEqual(len(target_options), 0)

    @patch('ospd_openvas.db.KbDB')
    def test_set_target(self, mock_kb):
        dummy = DummyDaemon()

        dummy.scan_collection.get_host_list = MagicMock(
            return_value='192.168.0.1'
        )

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_scan_preferences = MagicMock()
        p_handler.prepare_target_for_openvas()

        p_handler.kbdb.add_scan_preferences.assert_called_with(
            p_handler.scan_id,
            ['TARGET|||192.168.0.1'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_ports(self, mock_kb):
        dummy = DummyDaemon()

        dummy.scan_collection.get_ports = MagicMock(return_value='80,443')

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_scan_preferences = MagicMock()
        p_handler.prepare_ports_for_openvas()

        p_handler.kbdb.add_scan_preferences.assert_called_with(
            p_handler.scan_id,
            ['port_range|||80,443'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_main_kbindex(self, mock_kb):
        dummy = DummyDaemon()

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.kbdb.add_scan_preferences = Mock()
        p_handler.kbdb.index = 2
        p_handler.prepare_main_kbindex_for_openvas()

        p_handler.kbdb.add_scan_preferences.assert_called_with(
            p_handler.scan_id,
            ['ov_maindbid|||2'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_credentials(self, mock_kb):
        dummy = DummyDaemon()

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

        dummy.scan_collection.get_credentials = MagicMock(return_value=creds)

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_credentials_to_scan_preferences = MagicMock()
        ret = p_handler.prepare_credentials_for_openvas()

        self.assertTrue(ret)

    @patch('ospd_openvas.db.KbDB')
    def test_set_bad_credentials(self, mock_kb):
        dummy = DummyDaemon()

        # bad cred type shh instead of ssh
        creds = {
            'shh': {
                'type': 'ssh',
                'port': '22',
                'username': 'username',
                'password': 'pass',
            },
        }

        dummy.scan_collection.get_credentials = MagicMock(return_value=creds)

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_scan_preferences = MagicMock()
        ret = p_handler.prepare_credentials_for_openvas()

        self.assertFalse(ret)

    @patch('ospd_openvas.db.KbDB')
    def test_set_credentials_empty(self, mock_kb):
        dummy = DummyDaemon()

        creds = {}

        dummy.scan_collection.get_credentials = MagicMock(return_value=creds)

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_scan_preferences = MagicMock()
        ret = p_handler.prepare_credentials_for_openvas()

        self.assertTrue(ret)

    @patch('ospd_openvas.db.KbDB')
    def test_set_host_options(self, mock_kb):
        dummy = DummyDaemon()

        exc = '192.168.0.1'

        dummy.scan_collection.get_exclude_hosts = MagicMock(return_value=exc)

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_scan_preferences = MagicMock()
        p_handler.prepare_host_options_for_openvas()

        p_handler.kbdb.add_scan_preferences.assert_called_with(
            p_handler.scan_id,
            ['exclude_hosts|||192.168.0.1'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_host_options_none(self, mock_kb):
        dummy = DummyDaemon()

        exc = ''

        dummy.scan_collection.get_exclude_hosts = MagicMock(return_value=exc)

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_scan_preferences = MagicMock()
        p_handler.prepare_host_options_for_openvas()

        p_handler.kbdb.add_scan_preferences.assert_not_called()

    @patch('ospd_openvas.db.KbDB')
    def test_set_scan_params(self, mock_kb):
        dummy = DummyDaemon()

        ospd_param_dict = {
            'drop_privileges': {
                'type': 'boolean',
                'name': 'drop_privileges',
                'default': 0,
                'mandatory': 1,
                'description': '',
            },
        }

        opt = {'drop_privileges': 1}

        dummy.scan_collection.get_options = MagicMock(return_value=opt)

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_scan_preferences = MagicMock()
        p_handler.prepare_scan_params_for_openvas(ospd_param_dict)

        p_handler.kbdb.add_scan_preferences.assert_called_with(
            p_handler.scan_id, ['drop_privileges|||yes']
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_reverse_lookup_opt(self, mock_kb):
        dummy = DummyDaemon()

        t_opt = {'reverse_lookup_only': 1}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler.scan_id = '456-789'
        p_handler.kbdb.add_scan_preferences = MagicMock()
        p_handler.prepare_reverse_lookup_opt_for_openvas()

        p_handler.kbdb.add_scan_preferences.assert_called_with(
            p_handler.scan_id,
            [
                'reverse_lookup_only|||yes',
                'reverse_lookup_unify|||no',
            ],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_boreas_alive_test_with_settings(self, mock_kb):
        # No Boreas config setting (BOREAS_SETTING_NAME) set
        dummy = DummyDaemon()
        ov_setting = {'not_the_correct_setting': 1}
        t_opt = {}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            p_handler.kbdb.add_scan_preferences.assert_not_called()

        # Boreas config setting set but invalid alive_test.
        dummy = DummyDaemon()
        t_opt = {'alive_test': "error"}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||2'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # ALIVE_TEST_TCP_SYN_SERVICE as alive test.
        dummy = DummyDaemon()
        t_opt = {'alive_test': AliveTest.ALIVE_TEST_TCP_SYN_SERVICE}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||16'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # ICMP was chosen as alive test.
        dummy = DummyDaemon()
        t_opt = {'alive_test': AliveTest.ALIVE_TEST_ICMP}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||2'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # "Scan Config Default" as alive_test.
        dummy = DummyDaemon()
        t_opt = {'alive_test': AliveTest.ALIVE_TEST_SCAN_CONFIG_DEFAULT}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||2'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # TCP-SYN alive test and dedicated port list for alive scan provided.
        dummy = DummyDaemon()
        t_opt = {
            'alive_test_ports': "80,137",
            'alive_test': AliveTest.ALIVE_TEST_TCP_SYN_SERVICE,
        }
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [
                call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||16']),
                call(
                    p_handler.scan_id, [BOREAS_ALIVE_TEST_PORTS + '|||80,137']
                ),
            ]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

    @patch('ospd_openvas.db.KbDB')
    def test_set_boreas_alive_test_not_as_enum(self, mock_kb):
        # No Boreas config setting (BOREAS_SETTING_NAME) set
        dummy = DummyDaemon()
        ov_setting = {'not_the_correct_setting': 1}
        t_opt = {}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            p_handler.kbdb.add_scan_preferences.assert_not_called()

        # Boreas config setting set but invalid alive_test.
        dummy = DummyDaemon()
        t_opt = {'alive_test_methods': "1", 'arp': '-1'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||2'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # ICMP was chosen as alive test.
        dummy = DummyDaemon()
        t_opt = {'alive_test_methods': "1", 'icmp': '1'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||2'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # tcp_syn as alive test.
        dummy = DummyDaemon()
        t_opt = {'alive_test_methods': "1", 'tcp_syn': '1'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||16'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # tcp_ack as alive test.
        dummy = DummyDaemon()
        t_opt = {'alive_test_methods': "1", 'tcp_ack': '1'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||1'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # arp as alive test.
        dummy = DummyDaemon()
        t_opt = {'alive_test_methods': "1", 'arp': '1'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||4'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # arp as alive test.
        dummy = DummyDaemon()
        t_opt = {'alive_test_methods': "1", 'consider_alive': '1'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||8'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # all alive test methods
        dummy = DummyDaemon()
        t_opt = {
            'alive_test_methods': "1",
            'icmp': '1',
            'tcp_ack': '1',
            'tcp_syn': '1',
            'arp': '1',
            'consider_alive': '1',
        }
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||31'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

        # TCP-SYN alive test and dedicated port list for alive scan provided.
        dummy = DummyDaemon()
        t_opt = {
            'alive_test_ports': "80,137",
            'alive_test_methods': "1",
            'tcp_syn': '1',
        }
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            calls = [
                call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||16']),
                call(
                    p_handler.scan_id, [BOREAS_ALIVE_TEST_PORTS + '|||80,137']
                ),
            ]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

    @patch('ospd_openvas.db.KbDB')
    def test_set_boreas_alive_test_enum_has_precedence(self, mock_kb):
        dummy = DummyDaemon()
        t_opt = {
            'alive_test_methods': "1",
            'consider_alive': '1',
            'alive_test': AliveTest.ALIVE_TEST_ICMP,
        }
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {BOREAS_SETTING_NAME: 1}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            # has icmp and not consider_alive
            calls = [call(p_handler.scan_id, [BOREAS_ALIVE_TEST + '|||2'])]
            p_handler.kbdb.add_scan_preferences.assert_has_calls(calls)

    @patch('ospd_openvas.db.KbDB')
    def test_set_boreas_alive_test_without_settings(self, mock_kb):
        dummy = DummyDaemon()
        t_opt = {'alive_test': 16}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)
        ov_setting = {}
        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_boreas_alive_test()

            p_handler.kbdb.add_scan_preferences.assert_not_called()

    @patch('ospd_openvas.db.KbDB')
    def test_set_alive_no_setting(self, mock_kb):
        dummy = DummyDaemon()

        t_opt = {}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        ov_setting = {}

        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_alive_test_option_for_openvas()

            p_handler.kbdb.add_scan_preferences.assert_not_called()

    @patch('ospd_openvas.db.KbDB')
    def test_set_alive_no_invalid_alive_test(self, mock_kb):
        dummy = DummyDaemon()

        t_opt = {'alive_test': -1}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        ov_setting = {'some_setting': 1}

        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler._nvts_params = {}  # pylint: disable = protected-access
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_alive_test_option_for_openvas()

            p_handler.kbdb.add_scan_preferences.assert_not_called()

    @patch('ospd_openvas.db.KbDB')
    def test_set_alive_no_invalid_alive_test_no_enum(self, mock_kb):
        dummy = DummyDaemon()

        t_opt = {'alive_test_methods': '1', 'icmp': '-1'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        ov_setting = {'some_setting': 1}

        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler._nvts_params = {}  # pylint: disable = protected-access
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_alive_test_option_for_openvas()

            p_handler.kbdb.add_scan_preferences.assert_not_called()

    @patch('ospd_openvas.db.KbDB')
    def test_set_alive_pinghost(self, mock_kb):
        dummy = DummyDaemon()

        alive_test_out = [
            "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:2:checkbox:"
            "TCP ping tries also TCP-SYN ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:7:checkbox:"
            "TCP ping tries only TCP-SYN ping|||no",
            "1.3.6.1.4.1.25623.1.0.100315:3:checkbox:Do an ICMP ping|||yes",
            "1.3.6.1.4.1.25623.1.0.100315:4:checkbox:Use ARP|||no",
            "1.3.6.1.4.1.25623.1.0.100315:5:checkbox:"
            "Mark unrechable Hosts as dead (not scanning)|||yes",
        ]

        t_opt = {'alive_test': 2}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        ov_setting = {'some_setting': 1}

        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler._nvts_params = {}  # pylint: disable = protected-access
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_alive_test_option_for_openvas()

            for (
                key,
                value,
            ) in (
                p_handler._nvts_params.items()  # pylint: disable = protected-access
            ):
                self.assertTrue(
                    "{0}|||{1}".format(key, value) in alive_test_out
                )

    @patch('ospd_openvas.db.KbDB')
    def test_prepare_alive_test_not_supplied_as_enum(self, mock_kb):
        dummy = DummyDaemon()

        alive_test_out = {
            "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping": "no",
            "1.3.6.1.4.1.25623.1.0.100315:2:checkbox:"
            "TCP ping tries also TCP-SYN ping": "no",
            "1.3.6.1.4.1.25623.1.0.100315:7:checkbox:"
            "TCP ping tries only TCP-SYN ping": "no",
            "1.3.6.1.4.1.25623.1.0.100315:3:checkbox:Do an ICMP ping": "yes",
            "1.3.6.1.4.1.25623.1.0.100315:4:checkbox:Use ARP": "no",
            "1.3.6.1.4.1.25623.1.0.100315:5:checkbox:"
            "Mark unrechable Hosts as dead (not scanning)": "yes",
        }

        t_opt = {'alive_test_methods': '1', 'icmp': '1'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        ov_setting = {'some_setting': 1}

        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler._nvts_params = {}  # pylint: disable = protected-access
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_alive_test_option_for_openvas()

            self.assertEqual(
                p_handler._nvts_params,  # pylint: disable = protected-access
                alive_test_out,
            )

    @patch('ospd_openvas.db.KbDB')
    def test_prepare_alive_test_no_enum_no_alive_test(self, mock_kb):
        dummy = DummyDaemon()

        t_opt = {'alive_test_methods': '1', 'icmp': '0'}
        dummy.scan_collection.get_target_options = MagicMock(return_value=t_opt)

        ov_setting = {'some_setting': 1}

        with patch.object(Openvas, 'get_settings', return_value=ov_setting):
            p_handler = PreferenceHandler(
                '1234-1234', mock_kb, dummy.scan_collection, None
            )
            p_handler._nvts_params = {}  # pylint: disable = protected-access
            p_handler.scan_id = '456-789'
            p_handler.kbdb.add_scan_preferences = MagicMock()
            p_handler.prepare_alive_test_option_for_openvas()

            p_handler.kbdb.add_scan_preferences.assert_not_called()

    def test_alive_test_methods_to_bit_field(self):

        self.assertEqual(
            AliveTest.ALIVE_TEST_TCP_ACK_SERVICE,
            alive_test_methods_to_bit_field(
                icmp=False,
                tcp_ack=True,
                tcp_syn=False,
                arp=False,
                consider_alive=False,
            ),
        )

        self.assertEqual(
            AliveTest.ALIVE_TEST_ICMP,
            alive_test_methods_to_bit_field(
                icmp=True,
                tcp_ack=False,
                tcp_syn=False,
                arp=False,
                consider_alive=False,
            ),
        )

        self.assertEqual(
            AliveTest.ALIVE_TEST_ARP,
            alive_test_methods_to_bit_field(
                icmp=False,
                tcp_ack=False,
                tcp_syn=False,
                arp=True,
                consider_alive=False,
            ),
        )

        self.assertEqual(
            AliveTest.ALIVE_TEST_CONSIDER_ALIVE,
            alive_test_methods_to_bit_field(
                icmp=False,
                tcp_ack=False,
                tcp_syn=False,
                arp=False,
                consider_alive=True,
            ),
        )

        self.assertEqual(
            AliveTest.ALIVE_TEST_TCP_SYN_SERVICE,
            alive_test_methods_to_bit_field(
                icmp=False,
                tcp_ack=False,
                tcp_syn=True,
                arp=False,
                consider_alive=False,
            ),
        )

        all_alive_test_methods = (
            AliveTest.ALIVE_TEST_SCAN_CONFIG_DEFAULT
            | AliveTest.ALIVE_TEST_TCP_ACK_SERVICE
            | AliveTest.ALIVE_TEST_ICMP
            | AliveTest.ALIVE_TEST_ARP
            | AliveTest.ALIVE_TEST_CONSIDER_ALIVE
            | AliveTest.ALIVE_TEST_TCP_SYN_SERVICE
        )
        self.assertEqual(
            all_alive_test_methods,
            alive_test_methods_to_bit_field(
                icmp=True,
                tcp_ack=True,
                tcp_syn=True,
                arp=True,
                consider_alive=True,
            ),
        )

    @patch('ospd_openvas.db.KbDB')
    def test_prepare_nvt_prefs(self, mock_kb):
        dummy = DummyDaemon()

        alive_test_out = [
            "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping|||no"
        ]

        p_handler = PreferenceHandler(
            '1234-1234', mock_kb, dummy.scan_collection, None
        )
        p_handler._nvts_params = {  # pylint: disable = protected-access
            "1.3.6.1.4.1.25623.1.0.100315:1:checkbox:Do a TCP ping": "no"
        }
        p_handler.kbdb.add_scan_preferences = MagicMock()
        p_handler.prepare_nvt_preferences()

        p_handler.kbdb.add_scan_preferences.assert_called_with(
            p_handler.scan_id,
            alive_test_out,
        )

    @patch('ospd_openvas.db.KbDB')
    def test_prepare_nvt_prefs_no_prefs(self, mock_kb):
        dummy = DummyDaemon()

        p_handler = PreferenceHandler(
            '456-789', mock_kb, dummy.scan_collection, None
        )
        p_handler._nvts_params = {}  # pylint: disable = protected-access
        p_handler.kbdb.add_scan_preferences = MagicMock()
        p_handler.prepare_nvt_preferences()

        p_handler.kbdb.add_scan_preferences.assert_not_called()
