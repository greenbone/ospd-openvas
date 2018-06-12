# -*- coding: utf-8 -*-
# Description:
# Setup for the OSP OpenVAS Server
#
# Authors:
# Juan José Nicola <juan.nicola@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

import subprocess
import time
import os
import logging
import xml.etree.ElementTree as ET

from ospd.ospd import OSPDaemon
from ospd.misc import main as daemon_main
from ospd_openvas import __version__

import ospd_openvas.openvas_db as openvas_db

OSPD_DESC = """
This scanner runs 'OpenVAS Scanner' to scan the target hosts.

OpenVAS (Open Vulnerability Assessment System) is a powerful scanner
for vulnerabilities in IT infrastrucutres. The capabilities include
unauthzenticated scanning as well as authneticated scanning for
various types of systems and services.

For more details about OpenVAS see the OpenVAS homepage:
http://www.openvas.org/

The current version of ospd-openvas is a simple frame, which sends
the server parameters to the Greenbone Vulnerability Manager (GVM) and checks the
existence of OpenVAS Scanner binary. But it can not run scans yet.
"""

OSPD_PARAMS = {
    'auto_enable_dependencies': {
        'type': 'boolean',
        'name': 'auto_enable_dependencies',
        'default': 1,
        'mandatory': 1,
        'description': 'Automatically enable the plugins that are depended on',
    },
    'cgi_path': {
        'type' : 'string',
        'name': 'cgi_path',
        'default': '/cgi-bin:/scripts',
        'mandatory': 1,
        'description': 'Look for default CGIs in /cgi-bin and /scripts',
    },
    'checks_read_timeout': {
        'type' : 'integer',
        'name': 'checks_read_timeout',
        'default': 5,
        'mandatory': 1,
        'description': 'Number  of seconds that the security checks will wait for when doing a recv()',
    },
    'drop_privileges': {
        'type': 'boolean',
        'name': 'drop_privileges',
        'default': 0,
        'mandatory': 1,
        'description': '',
    },
    'network_scan': {
        'type': 'boolean',
        'name': 'network_scan',
        'default': 0,
        'mandatory': 1,
        'description': '',
    },
    'non_simult_ports': {
        'type' : 'string',
        'name': 'non_simult_ports',
        'default': '139, 445, 3389, Services/irc',
        'mandatory': 1,
        'description': 'Prevent to make two connections on the same given ports at the same time.',
    },
    'open_sock_max_attempts': {
        'type' : 'integer',
        'name': 'open_sock_max_attempts',
        'default': 5,
        'mandatory': 0,
        'description': 'Number of unsuccessful retries to open the socket before to set the port as closed.',
    },
    'timeout_retry': {
        'type' : 'integer',
        'name': 'timeout_retry',
        'default': 5,
        'mandatory': 0,
        'description': 'Number of retries when a socket connection attempt timesout.',
    },
    'optimize_test': {
        'type' : 'integer',
        'name': 'optimize_test',
        'default': 5,
        'mandatory': 0,
        'description': 'By default, openvassd does not trust the remote host banners.',
    },
    'plugins_timeout': {
        'type' : 'integer',
        'name': 'plugins_timeout',
        'default': 5,
        'mandatory': 0,
        'description': 'This is the maximum lifetime, in seconds of a plugin.',
    },
    'report_host_details': {
        'type': 'boolean',
        'name': 'report_host_details',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'safe_checks': {
        'type': 'boolean',
        'name': 'safe_checks',
        'default': 1,
        'mandatory': 1,
        'description': 'Disable the plugins with potential to crash the remote services',
    },
    'scanner_plugins_timeout': {
        'type' : 'integer',
        'name': 'scanner_plugins_timeout',
        'default': 36000,
        'mandatory': 1,
        'description': 'Like plugins_timeout, but for ACT_SCANNER plugins.',
    },
    'time_between_request': {
        'type' : 'integer',
        'name': 'time_between_request',
        'default': 0,
        'mandatory': 0,
        'description': 'Allow to set a wait time between two actions (open, send, close).',
    },
    'unscanned_closed': {
        'type': 'boolean',
        'name': 'unscanned_closed',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'unscanned_closed_udp': {
        'type': 'boolean',
        'name': 'unscanned_closed_udp',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'use_mac_addr': {
        'type': 'boolean',
        'name': 'use_mac_addr',
        'default': 0,
        'mandatory': 0,
        'description': 'To test the local network. Hosts will be referred to by their MAC address.',
    },
    'vhosts': {
        'type' : 'string',
        'name': 'vhosts',
        'default': '',
        'mandatory': 0,
        'description': '',
    },
    'vhosts_ip': {
        'type' : 'string',
        'name': 'vhosts_ip',
        'default': '',
        'mandatory': 0,
        'description': '',
    },
}

class OSPDopenvas(OSPDaemon):

    """ Class for ospd-openvas daemon. """

    def __init__(self, certfile, keyfile, cafile):
        """ Initializes the ospd-openvas daemon's internal data. """
        global COMMANDS_TABLE

        super(OSPDopenvas, self).__init__(certfile=certfile, keyfile=keyfile,
                                    cafile=cafile)
        self.server_version = __version__
        self.scanner_info['name'] = 'openvassd'
        self.scanner_info['version'] = '' # achieved during self.check()
        self.scanner_info['description'] = OSPD_DESC
        for name, param in OSPD_PARAMS.items():
            self.add_scanner_param(name, param)

        if openvas_db.db_init() is False:
            self.add_scan_error(scan_id, host=target,
                 value='OpenVAS Redis Error: Not possible' +
                       'to find db_connection.')
            return 2

        ctx = openvas_db.db_find('nvticache10')
        openvas_db.set_global_redisctx(ctx)
        self.load_vts()

    def parse_param(self):
        """ Set OSPD_PARAMS with the params taken from the openvas_scanner. """
        global OSPD_PARAMS
        result = subprocess.check_output(['openvassd', '-s'],
                                         stderr=subprocess.STDOUT)
        result = result.decode('ascii')
        param_list = dict()
        for conf in result.split('\n'):
            elem = conf.split('=')
            if len(elem) == 2:
                param_list[str.strip(elem[0])] = str.strip(elem[1])
        for elem in OSPD_PARAMS:
            if elem in param_list:
                OSPD_PARAMS[elem]['default'] = param_list[elem]

    def load_vts(self):
        """ Load the NVT's OIDs and their filename into the vts
        global  dictionary. """
        oids = openvas_db.get_pattern('filename:*:oid')
        for oid in oids:
            vt_id = oid[1].pop()
            ret = self.add_vt(vt_id, name=oid[0])
            if ret == -1:
                logger.info("Dupplicated VT with OID: {0}".format(vt_id))
            if ret == -2:
                logger.info("{0}: Invalid OID.".format(vt_id))

    def check(self):
        """ Checks that openvassd command line tool is found and
        is executable. """
        try:
            result = subprocess.check_output(['openvassd', '-V'],
                                             stderr=subprocess.STDOUT)
            result = result.decode('ascii')
        except OSError:
            # the command is not available
            return False

        if result is None:
            return False

        version = result.find('OpenVAS')
        if version < 0:
            return False

        self.parse_param()
        self.scanner_info['version'] = result.replace('\n', '. ')
        return True


    def exec_scan(self, scan_id, target):
        """ Starts the OpenVAS scanner for scan_id scan. """

        # Create a general log entry about executing OpenVAS
        # It is important to send at least one result, otherwise
        # the host details won't be stored.
        self.add_scan_log(scan_id, host=target, name='OpenVAS summary',
                          value='An OpenVAS Scanner was started for %s.'
                          % target)
        return 1

def main():
    """ OSP openvas main function. """
    daemon_main('OSPD - openvas wrapper', OSPDopenvas)
