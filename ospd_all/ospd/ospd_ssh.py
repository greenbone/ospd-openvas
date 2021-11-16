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

""" OSP Daemon class for simple remote SSH-based command execution.
"""


# This is needed for older pythons as our current module is called the same
# as the ospd package
# Another solution would be to rename that file.
from __future__ import absolute_import

import socket

from typing import Optional, Dict
from ospd.ospd import OSPDaemon

try:
    import paramiko
except ImportError:
    paramiko = None

SSH_SCANNER_PARAMS = {
    'username_password': {
        'type': 'credential_up',
        'name': 'SSH credentials',
        'default': '',
        'mandatory': 0,
        'description': 'The SSH credentials in username:password format. Used'
        ' to log into the target and to run the commands on'
        ' that target. This should not be a privileged user'
        ' like "root", a regular privileged user account'
        ' should be sufficient in most cases.',
    },
    'port': {
        'type': 'integer',
        'name': 'SSH Port',
        'default': 22,
        'mandatory': 0,
        'description': 'The SSH port which to use for logging in with the'
        ' given username_password.',
    },
    'ssh_timeout': {
        'type': 'integer',
        'name': 'SSH timeout',
        'default': 30,
        'mandatory': 0,
        'description': 'Timeout when communicating with the target via SSH.',
    },
}  # type: Dict

# pylint: disable=abstract-method
class OSPDaemonSimpleSSH(OSPDaemon):

    """
    OSP Daemon class for simple remote SSH-based command execution.

    This class automatically adds scanner parameters to handle remote
    ssh login into the target systems: username, password, port and
    ssh_timout

    The method run_command can be used to execute a single command
    on the given remote system. The stdout result is returned as
    an array.
    """

    def __init__(self, **kwargs):
        """Initializes the daemon and add parameters needed to remote SSH
        execution."""
        super().__init__(**kwargs)

        self._niceness = kwargs.get('niceness', None)

        if paramiko is None:
            raise ImportError(
                'paramiko needs to be installed in order to use'
                ' the %s class.' % self.__class__.__name__
            )

        for name, param in SSH_SCANNER_PARAMS.items():
            self.set_scanner_param(name, param)

    def run_command(self, scan_id: str, host: str, cmd: str) -> Optional[str]:
        """
        Run a single command via SSH and return the content of stdout or
        None in case of an Error. A scan error is issued in the latter
        case.

        For logging into 'host', the scan options 'port', 'username',
        'password' and 'ssh_timeout' are used.
        """

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        options = self.get_scan_options(scan_id)

        port = int(options['port'])
        timeout = int(options['ssh_timeout'])

        # For backward compatibility, consider the legacy mode to get
        # credentials as scan_option.
        # First and second modes should be removed in future releases.
        # On the third case it receives the credentials as a subelement of
        # the <target>.
        credentials = self.get_scan_credentials(scan_id)
        if (
            'username_password' in options
            and ':' in options['username_password']
        ):
            username, password = options['username_password'].split(':', 1)
        elif 'username' in options and options['username']:
            username = options['username']
            password = options['password']
        elif credentials:
            cred_params = credentials.get('ssh')
            username = cred_params.get('username', '')
            password = cred_params.get('password', '')
        else:
            self.add_scan_error(
                scan_id, host=host, value='Erroneous username_password value'
            )
            raise ValueError('Erroneous username_password value')

        try:
            ssh.connect(
                hostname=host,
                username=username,
                password=password,
                timeout=timeout,
                port=port,
            )
        except (
            paramiko.ssh_exception.AuthenticationException,
            socket.error,
        ) as err:
            # Errors: No route to host, connection timeout, authentication
            # failure etc,.
            self.add_scan_error(scan_id, host=host, value=str(err))
            return None

        if self._niceness is not None:
            cmd = "nice -n %s %s" % (self._niceness, cmd)
        _, stdout, _ = ssh.exec_command(cmd)
        result = stdout.readlines()
        ssh.close()

        return result
