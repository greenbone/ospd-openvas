# -*- coding: utf-8 -*-
# $Id$
# Description:
# OSP Daemon class for simple remote SSH-based command execution.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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

""" OSP Daemon class for simple remote SSH-based command execution. """

from ospd import OSPDaemon

import socket
import paramiko

SSH_SCANNER_PARAMS = {
    'username':
     {'type': 'string',
      'name': 'SSH Username',
      'default': '',
      'description': 'The SSH username used to log into the target and to run'
                     ' the commands on that target.',},
     'password':
     {'type': 'password',
      'name': 'SSH Password',
      'default': '',
      'description': 'The SSH password for the given username which is used to'
                     ' log into the target and to run the commands'
                     ' on that target. This should not be a privileged user'
                     ' like "root", a regular privileged user account should be'
                     ' sufficient in most cases.',},
     'port':
     {'type': 'integer',
      'name': 'SSH Port',
      'default': 22,
      'description': 'The SSH port which to use for logging in with the given'
                     ' username/password.'
                     ' target.',},
     'ssh_timeout':
     {'type': 'integer',
      'name': 'SSH timeout',
      'default': 30,
      'description': 'Timeout when communicating with the target via SSH.',},}


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

    def __init__(self, certfile, keyfile, cafile):
        """ Initializes the daemon and add parameters needed to remote SSH execution. """

        super(OSPDaemonSimpleSSH, self).__init__(certfile=certfile, keyfile=keyfile,
                                                 cafile=cafile)

        for name, param in SSH_SCANNER_PARAMS.items():
            self.add_scanner_param(name, param)

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def run_command(self, scan_id, host='', cmd=''):
        """
        Run a single command via SSH and return the content of stdout or
        None in case of an Error. A scan error is issued in the latter
        case.

        For logging into 'host', the scan options 'port', 'username',
        'password' and 'ssh_timeout' are used.
        """

        options = self.get_scan_options(scan_id)

        port = int(options['port'])
        timeout = int(options['ssh_timeout'])

        try:
            self.ssh.connect(hostname=host, username=options['username'],
                             password=options['password'], timeout=timeout,
                             port=port)
        except (paramiko.ssh_exception.AuthenticationException,
                socket.error) as err:
            # Errors: No route to host, connection timeout, authentication
            # failure etc,.
            self.add_scan_error(scan_id, host=host, value=str(err))
            return None

        _, stdout, _ = self.ssh.exec_command(cmd)
        result = stdout.readlines()
        self.ssh.close()

        return result
