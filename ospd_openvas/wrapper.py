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
import signal
import psutil

from ospd.ospd import OSPDaemon, logger
from ospd.misc import main as daemon_main
from ospd.misc import target_str_to_list
from ospd_openvas import __version__

import ospd_openvas.nvticache as nvti
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
the server parameters to the Greenbone Vulnerability Manager (GVM) and checks
the existence of OpenVAS Scanner binary. But it can not run scans yet.
"""

MAIN_KBINDEX = None

OSPD_PARAMS = {
    'auto_enable_dependencies': {
        'type': 'boolean',
        'name': 'auto_enable_dependencies',
        'default': 1,
        'mandatory': 1,
        'description': 'Automatically enable the plugins that are depended on',
    },
    'cgi_path': {
        'type': 'string',
        'name': 'cgi_path',
        'default': '/cgi-bin:/scripts',
        'mandatory': 1,
        'description': 'Look for default CGIs in /cgi-bin and /scripts',
    },
    'checks_read_timeout': {
        'type': 'integer',
        'name': 'checks_read_timeout',
        'default': 5,
        'mandatory': 1,
        'description': ('Number  of seconds that the security checks will ' +
                        'wait for when doing a recv()'),
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
        'type': 'string',
        'name': 'non_simult_ports',
        'default': '139, 445, 3389, Services/irc',
        'mandatory': 1,
        'description': ('Prevent to make two connections on the same given ' +
                        'ports at the same time.'),
    },
    'open_sock_max_attempts': {
        'type': 'integer',
        'name': 'open_sock_max_attempts',
        'default': 5,
        'mandatory': 0,
        'description': ('Number of unsuccessful retries to open the socket ' +
                        'before to set the port as closed.'),
    },
    'timeout_retry': {
        'type': 'integer',
        'name': 'timeout_retry',
        'default': 5,
        'mandatory': 0,
        'description': ('Number of retries when a socket connection attempt ' +
                        'timesout.'),
    },
    'optimize_test': {
        'type': 'integer',
        'name': 'optimize_test',
        'default': 5,
        'mandatory': 0,
        'description': ('By default, openvassd does not trust the remote ' +
                        'host banners.'),
    },
    'plugins_timeout': {
        'type': 'integer',
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
        'description': ('Disable the plugins with potential to crash ' +
                        'the remote services'),
    },
    'scanner_plugins_timeout': {
        'type': 'integer',
        'name': 'scanner_plugins_timeout',
        'default': 36000,
        'mandatory': 1,
        'description': 'Like plugins_timeout, but for ACT_SCANNER plugins.',
    },
    'time_between_request': {
        'type': 'integer',
        'name': 'time_between_request',
        'default': 0,
        'mandatory': 0,
        'description': ('Allow to set a wait time between two actions ' +
                        '(open, send, close).'),
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
        'description': 'To test the local network. ' +
                       'Hosts will be referred to by their MAC address.',
    },
    'vhosts': {
        'type': 'string',
        'name': 'vhosts',
        'default': '',
        'mandatory': 0,
        'description': '',
    },
    'vhosts_ip': {
        'type': 'string',
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

        super(OSPDopenvas, self).__init__(certfile=certfile, keyfile=keyfile,
                                          cafile=cafile)
        self.server_version = __version__
        self.scanner_info['name'] = 'openvassd'
        self.scanner_info['version'] = ''  # achieved during self.check()
        self.scanner_info['description'] = OSPD_DESC
        for name, param in OSPD_PARAMS.items():
            self.add_scanner_param(name, param)

        if openvas_db.db_init() is False:
            logger.error('OpenVAS Redis Error: Not possible '
                         'to find db_connection.')
            raise Exception

        ctx = openvas_db.db_find(nvti.NVTICACHE_STR)
        if not ctx:
            self.redis_nvticache_init()
            ctx = openvas_db.db_find(nvti.NVTICACHE_STR)
        openvas_db.set_global_redisctx(ctx)
        self.load_vts()

    def parse_param(self):
        """ Set OSPD_PARAMS with the params taken from the openvas_scanner. """
        global OSPD_PARAMS
        bool_dict = {'no': 0, 'yes': 1}

        result = subprocess.check_output(['openvassd', '-s'],
                                         stderr=subprocess.STDOUT)
        result = result.decode('ascii')
        param_list = dict()
        for conf in result.split('\n'):
            elem = conf.split('=')
            if len(elem) == 2:
                value = str.strip(elem[1])
                if str.strip(elem[1]) in bool_dict:
                    value = bool_dict[value]
                param_list[str.strip(elem[0])] = value
        for elem in OSPD_PARAMS:
            if elem in param_list:
                OSPD_PARAMS[elem]['default'] = param_list[elem]

    def redis_nvticache_init(self):
        """ Loads NVT's metadata into Redis DB. """
        try:
            logger.debug('Loading NVTs in Redis DB')
            subprocess.check_call(['openvassd', '-C'])
        except subprocess.CalledProcessError as err:
            logger.error('OpenVAS Scanner failed to load NVTs.')
            raise err

    def load_vts(self):
        """ Load the NVT's OIDs and their filename into the vts
        global  dictionary. """
        oids = nvti.get_oids()
        str_out = True
        for oid in oids:
            vt_id = oid[1]
            filename = oid[0].split(':')
            ret = self.add_vt(vt_id,
                              name=filename[1],
                              vt_params=nvti.get_nvt_params(vt_id, str_out),
                              custom=nvti.get_nvt_metadata(vt_id, str_out))
            if ret == -1:
                logger.info("Dupplicated VT with OID: {0}".format(vt_id))
            if ret == -2:
                logger.info("{0}: Invalid OID.".format(vt_id))

    @staticmethod
    def get_custom_vt_as_xml_str(custom):
        """ Return custom since it is already formated as string. """
        return custom

    @staticmethod
    def get_params_vt_as_xml_str(vt_params):
        """ Return custom since it is already formated as string. """
        return vt_params

    def check(self):
        """ Checks that openvassd command line tool is found and
        is executable. """
        try:
            result = subprocess.check_output(['openvassd', '-V'],
                                             stderr=subprocess.STDOUT)
            result = result.decode('ascii')
        except OSError:
            # The command is not available
            return False

        if result is None:
            return False

        version = result.split('\n')
        if version[0].find('OpenVAS') < 0:
            return False

        self.parse_param()
        self.scanner_info['version'] = version[0]

        return True

    def update_progress(self, scan_id, target, msg):
        """ Calculate porcentage and update the scan status
        for the progress bar. """
        host_progress_dict = dict()
        prog = str.split(msg, '/')
        if prog[1] == 0:
            return
        host_prog = (float(prog[0]) / float(prog[1])) * 100
        host_progress_dict[target] = host_prog
        total_host = len(target_str_to_list(target))
        self.set_scan_progress(scan_id,
                               sum(host_progress_dict.values()) / total_host)

    def get_openvas_status(self, scan_id, target):
        """ Get all status entries from redis kb. """
        res = openvas_db.get_status()
        while res:
            self.update_progress(scan_id, target, res)
            res = openvas_db.get_status()

    def get_openvas_result(self, scan_id):
        """ Get all result entries from redis kb. """
        res = openvas_db.get_result()
        while res:
            msg = res.split('|||')
            if msg[1] == '':
                host_aux = openvas_db.item_get_single('internal/ip')
            else:
                host_aux = msg[1]
            if msg[0] == 'ERRMSG':
                self.add_scan_error(scan_id, host=host_aux,
                                    name=msg[3], value=msg[4], port=msg[2])
            if msg[0] == 'LOG':
                self.add_scan_log(scan_id, host=host_aux, name=msg[3],
                                  value=msg[4], port=msg[2])
            if msg[0] == 'ALARM':
                self.add_scan_alarm(scan_id, host=host_aux, name=msg[3],
                                    value=msg[4], port=msg[2], qod='97',
                                    severity='7.5')
            res = openvas_db.get_result()

    def get_openvas_timestamp_scan_host(self, scan_id, target):
        """ Get start and end timestamp of a host scan from redis kb. """
        timestamp = openvas_db.get_host_scan_scan_end_time()
        if timestamp:
            self.add_scan_log(scan_id, host=target, name='HOST_END',
                              value=timestamp)
            return
        timestamp = openvas_db.get_host_scan_scan_start_time()
        if timestamp:
            self.add_scan_log(scan_id, host=target, name='HOST_START',
                              value=timestamp)
            return

    def scan_is_finished(self, scan_id):
        """ Check if the scan has finished. """
        status = openvas_db.item_get_single(('internal/%s' % scan_id))
        return status == 'finished'

    def scan_is_stopped(self, scan_id):
        """ Check if the parent process has recieved the stop_scan order.
        @in scan_id: ID to identify the scan to be stopped.
        @return 1 if yes, None in oder case.
        """
        ctx = openvas_db.kb_connect(dbnum=MAIN_KBINDEX)
        openvas_db.set_global_redisctx(ctx)
        status = openvas_db.item_get_single(('internal/%s' % scan_id))
        return status == 'stop_all'

    def stop_scan(self, scan_id):
        """ Set a key in redis to indicate the wrapper process that it
        must kill the childs. It is done through redis because this a new
        multiprocess instance and it is not possible to reach the variables
        of the grandchild process. Then, a clean up is performed before
        terminating. """
        ctx = openvas_db.db_find('internal/%s' % scan_id)
        openvas_db.set_global_redisctx(ctx)
        openvas_db.item_set_single(('internal/%s' % scan_id), ['stop_all', ])
        while 1:
            time.sleep(1)
            if openvas_db.item_get_single('internal/%s' % scan_id):
                continue
            break

    def do_cleanup(self, ovas_pid):
        """ Send SIGUSR1 to OpenVAS process to stop the scan. """
        parent = psutil.Process(ovas_pid)
        children = parent.children(recursive=True)
        for process in children:
            if process.ppid() == int(ovas_pid):
                logger.debug('Stopping process: {0}'.format(process))
                os.kill(process.pid, signal.SIGUSR1)

    @staticmethod
    def process_vts(vts):
        """ Add single VTs and their parameters. """
        vts_list = []
        vts_params = []
        ctx = openvas_db.db_find(nvti.NVTICACHE_STR)
        for memb in vts.items():
            vts_list.append(memb[0])
            nvt_name = nvti.get_nvt_name(ctx, memb[0])
            for i in memb[1].items():
                param = ["{0}[{1}]:{2}".format(nvt_name, i[1]['type'], i[0]),
                         str(i[1]['value'])]
                vts_params.append(param)
        return vts_list, vts_params

    def exec_scan(self, scan_id, target):
        """ Starts the OpenVAS scanner for scan_id scan. """
        global MAIN_KBINDEX
        ports = self.get_scan_ports(scan_id, target)
        if not ports:
            self.add_scan_error(scan_id, name='', host=target,
                                value='No port list defined.')
            return 2

        # Get scan options
        options = self.get_scan_options(scan_id)
        prefs_val = []
        ctx = openvas_db.kb_new()
        openvas_db.set_global_redisctx(ctx)
        MAIN_KBINDEX = openvas_db.DB_INDEX

        openvas_db.item_add_single(('internal/%s' % scan_id), ['new', ])

        # Set scan preferences
        for item in options.items():
            prefs_val.append(item[0] + "|||" + str(item[1]))
        openvas_db.item_add_single(str('internal/%s/scanprefs' % scan_id),
                                   prefs_val)

        # Set target
        target_aux = ('TARGET|||%s' % target)
        openvas_db.item_add_single(('internal/%s/scanprefs' % scan_id),
                                   [target_aux, ])
        # Set port range
        port_range = ('port_range|||%s' % ports)
        openvas_db.item_add_single(('internal/%s/scanprefs' % scan_id),
                                   [port_range, ])
        # Set plugins to run
        nvts = self.get_scan_vts(scan_id)
        if nvts != '':
            nvts_list, nvts_params = self.process_vts(nvts)
            # Add nvts list
            separ = ';'
            plugin_list = ('plugin_set|||%s' % separ.join(nvts_list))
            openvas_db.item_add_single(('internal/%s/scanprefs' % scan_id),
                                       [plugin_list, ])
            # Add nvts parameters
            for elem in nvts_params:
                item = ('%s|||%s' % (elem[0], elem[1]))
                openvas_db.item_add_single(('internal/%s/scanprefs' % scan_id),
                                           [item, ])
        else:
            openvas_db.release_db(MAIN_KBINDEX)
            self.add_scan_error(scan_id, name='', host=target,
                                value='No VTS to run.')
            return 2

        # Create a general log entry about executing OpenVAS
        # It is important to send at least one result, otherwise
        # the host details won't be stored.
        self.add_scan_log(scan_id, host=target, name='OpenVAS summary',
                          value='An OpenVAS Scanner was started for %s.'
                          % target)

        self.add_scan_log(scan_id, host=target, name='KB location Found',
                          value='KB location path was found: %s.'
                          % openvas_db.DB_ADDRESS)

        self.add_scan_log(scan_id, host=target, name='Feed Update',
                          value='Feed version: %s.'
                          % nvti.get_feed_version())

        cmd = ['openvassd', '--scan-start', scan_id]
        try:
            result = subprocess.Popen(cmd, shell=False)
        except OSError:
            # the command is not available
            return False

        ovas_pid = result.pid
        logger.debug('pid = {0}'.format(ovas_pid))

        no_id_found = False
        while 1:
            time.sleep(3)

            # Check if the client stopped the whole scan
            if self.scan_is_stopped(scan_id):
                self.do_cleanup(ovas_pid)

            for i in range(1, openvas_db.MAX_DBINDEX):
                if i == MAIN_KBINDEX:
                    continue
                ctx = openvas_db.kb_connect(i)
                openvas_db.set_global_redisctx(ctx)
                id_aux = openvas_db.item_get_single('internal/scan_id')
                if not id_aux:
                    continue
                if id_aux == scan_id:
                    no_id_found = False
                    self.get_openvas_timestamp_scan_host(scan_id, target)
                    self.get_openvas_result(scan_id)
                    self.get_openvas_status(scan_id, target)

                    if self.scan_is_finished(scan_id):
                        openvas_db.release_db(i)
            # Scan end. No kb in use for this scan id
            if no_id_found:
                break
            no_id_found = True

        # Delete keys from KB related to this scan task.
        openvas_db.release_db(MAIN_KBINDEX)
        return 1


def main():
    """ OSP openvas main function. """
    daemon_main('OSPD - openvas wrapper', OSPDopenvas)
