# -*- coding: utf-8 -*-
# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

import logging

from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock

from ospd.vts import Vts

from tests.dummydaemon import DummyDaemon
from tests.helper import assert_called_once

import ospd_openvas.db

from ospd_openvas.preferencehandler import PreferenceHandler


class PreferenceHandlerTestCase(TestCase):
    @patch('ospd_openvas.db.KbDB')
    def test_process_vts_not_found(self, mock_kb):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100065': {'3': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }
        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection)

        w.load_vts()
        w.temp_vts = w.vts
        p.process_vts(vts, w.temp_vts)

        assert_called_once(logging.Logger.warning)

    def test_process_vts_bad_param_id(self):
        w = DummyDaemon()

        vts = {
            '1.3.6.1.4.1.25623.1.0.100061': {'3': 'new value'},
            'vt_groups': ['family=debian', 'family=general'],
        }

        p = PreferenceHandler('1234-1234', None, w.scan_collection)

        w.load_vts()
        w.temp_vts = w.vts
        ret = p.process_vts(vts, w.temp_vts)

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

        p = PreferenceHandler('1234-1234', None, w.scan_collection)

        w.load_vts()
        w.temp_vts = w.vts

        ret = p.process_vts(vts, w.temp_vts)

        self.assertEqual(ret, vt_out)

    @patch('ospd_openvas.db.KbDB')
    def test_set_plugins_false(self, mock_kb):
        w = DummyDaemon()

        w.scan_collection.get_vts = Mock()
        w.scan_collection.get_vts.return_value = {}
        w.load_vts()
        w.temp_vts = w.vts

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection)
        p.kbdb.add_scan_preferences = Mock()
        r = p.set_plugins(w.temp_vts)

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
        w.load_vts()
        w.temp_vts = w.vts

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection)
        p.kbdb.add_scan_preferences = Mock()
        r = p.set_plugins(w.temp_vts)

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
        p = PreferenceHandler('1234-1234', None, w.scan_collection)

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

        p = PreferenceHandler('1234-1234', None, w.scan_collection)
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

        p = PreferenceHandler('1234-1234', None, w.scan_collection)
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
        p = PreferenceHandler('1234-1234', None, w.scan_collection)
        ret = p.build_alive_test_opt_as_prefs(target_options_dict)

        self.assertEqual(ret, alive_test_out)

    def test_build_alive_test_opt_fail_1(self):
        w = DummyDaemon()
        logging.Logger.debug = Mock()

        target_options_dict = {'alive_test': 'a'}
        p = PreferenceHandler('1234-1234', None, w.scan_collection)
        target_options = p.build_alive_test_opt_as_prefs(target_options_dict)

        assert_called_once(logging.Logger.debug)
        self.assertEqual(len(target_options), 0)

    @patch('ospd_openvas.db.KbDB')
    def test_set_target(self, mock_kb):
        w = DummyDaemon()

        w.scan_collection.get_host_list = MagicMock(return_value='192.168.0.1')

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        p.set_target()

        p.kbdb.add_scan_preferences.assert_called_with(
            p._openvas_scan_id, ['TARGET|||192.168.0.1'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_ports(self, mock_kb):
        w = DummyDaemon()

        w.scan_collection.get_ports = MagicMock(return_value='80,443')

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        p.set_ports()

        p.kbdb.add_scan_preferences.assert_called_with(
            p._openvas_scan_id, ['port_range|||80,443'],
        )

    @patch('ospd_openvas.db.KbDB')
    def test_set_main_kbindex(self, mock_kb):
        w = DummyDaemon()

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection)
        p.kbdb.add_scan_preferences = MagicMock()
        p.set_main_kbindex(2)

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

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        r = p.set_credentials()

        self.assertTrue(r)
        p.kbdb.add_scan_preferences.assert_called_once()

    @patch('ospd_openvas.db.KbDB')
    def test_set_credentials_false(self, mock_kb):
        w = DummyDaemon()

        creds = {}

        w.scan_collection.get_credentials = MagicMock(return_value=creds)

        p = PreferenceHandler('1234-1234', mock_kb, w.scan_collection)
        p._openvas_scan_id = '456-789'
        p.kbdb.add_scan_preferences = MagicMock()
        r = p.set_credentials()

        self.assertFalse(r)
