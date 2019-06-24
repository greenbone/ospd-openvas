# Copyright (C) 2015-2018 Greenbone Networks GmbH
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

""" Test module for ospd ssh support.
"""

import unittest

from ospd import ospd_ssh
from ospd.ospd_ssh import OSPDaemonSimpleSSH


class FakeFile(object):
    def __init__(self, content):
        self.content = content

    def readlines(self):
        return self.content.split('\n')


commands = None  # pylint: disable=invalid-name


class FakeSSHClient(object):
    def __init__(self):
        global commands
        commands = []

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, **kwargs):
        pass

    def exec_command(self, cmd):
        commands.append(cmd)
        return None, FakeFile(''), None

    def close(self):
        pass


class FakeExceptions(object):
    AuthenticationException = None  # pylint: disable=invalid-name


class fakeparamiko(object):  # pylint: disable=invalid-name
    @staticmethod
    def SSHClient(*args):  # pylint: disable=invalid-name
        return FakeSSHClient(*args)

    @staticmethod
    def AutoAddPolicy():  # pylint: disable=invalid-name
        pass

    ssh_exception = FakeExceptions


class SSHDaemonTestCase(unittest.TestCase):
    def test_no_paramiko(self):
        ospd_ssh.paramiko = None

        with self.assertRaises(ImportError):
            OSPDaemonSimpleSSH('cert', 'key', 'ca', '10')

    def test_run_command(self):
        ospd_ssh.paramiko = fakeparamiko
        daemon = OSPDaemonSimpleSSH('cert', 'key', 'ca', '10')
        scanid = daemon.create_scan(
            None,
            [['host.example.com', '80, 443', '', '']],
            dict(port=5, ssh_timeout=15, username_password='dummy:pw'),
            '',
        )

        res = daemon.run_command(scanid, 'host.example.com', 'cat /etc/passwd')

        self.assertIsInstance(res, list)
        self.assertEqual(commands, ['nice -n 10 cat /etc/passwd'])

    def test_run_command_legacy_credential(self):
        ospd_ssh.paramiko = fakeparamiko

        daemon = OSPDaemonSimpleSSH('cert', 'key', 'ca', '10')
        scanid = daemon.create_scan(
            None,
            [['host.example.com', '80, 443', '', '']],
            dict(port=5, ssh_timeout=15, username='dummy', password='pw'),
            '',
        )

        res = daemon.run_command(scanid, 'host.example.com', 'cat /etc/passwd')

        self.assertIsInstance(res, list)
        self.assertEqual(commands, ['nice -n 10 cat /etc/passwd'])

    def test_run_command_new_credential(self):
        ospd_ssh.paramiko = fakeparamiko

        daemon = OSPDaemonSimpleSSH('cert', 'key', 'ca', '10')

        cred_dict = {
            'ssh': {
                'type': 'up',
                'password': 'mypass',
                'port': '22',
                'username': 'scanuser',
            },
            'smb': {'type': 'up', 'password': 'mypass', 'username': 'smbuser'},
        }

        scanid = daemon.create_scan(
            None,
            [['host.example.com', '80, 443', cred_dict, '']],
            dict(port=5, ssh_timeout=15),
            '',
        )
        res = daemon.run_command(scanid, 'host.example.com', 'cat /etc/passwd')

        self.assertIsInstance(res, list)
        self.assertEqual(commands, ['nice -n 10 cat /etc/passwd'])

    def test_run_command_no_credential(self):
        ospd_ssh.paramiko = fakeparamiko

        daemon = OSPDaemonSimpleSSH('cert', 'key', 'ca', '10')
        scanid = daemon.create_scan(
            None,
            [['host.example.com', '80, 443', '', '']],
            dict(port=5, ssh_timeout=15),
            '',
        )

        with self.assertRaises(ValueError):
            daemon.run_command(scanid, 'host.example.com', 'cat /etc/passwd')
