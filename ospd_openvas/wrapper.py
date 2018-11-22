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
import signal
import uuid
from lxml.etree import tostring, SubElement, Element
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

PENDING_FEED = None

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

    def check_feed(self):
        """ Check if there is a feed update. Wait until all the running
        scans finished. Set a flag to anounce there is a pending feed update,
        which avoid to start a new scan.
        """
        global PENDING_FEED
        if self.get_feed_version() != nvti.get_feed_version():
            for scan_id in self.scan_processes:
                if self.scan_processes[scan_id].is_alive():
                    if not PENDING_FEED:
                        logger.debug(
                            'There is a running scan. Therefore the feed '
                            'update will be performed later.')
                        PENDING_FEED = True
                    return

            self.vts = dict()
            self.load_vts()

    def scheduler(self):
        """This method is called periodically to run tasks."""
        self.check_feed()

    def load_vts(self):
        """ Load the NVT's metadata into the vts
        global  dictionary. """
        logger.debug('Loading vts in memory.')
        global PENDING_FEED
        oids = dict(nvti.get_oids())
        for filename, vt_id in oids.items():
            _vt_params = nvti.get_nvt_params(vt_id)
            _vt_refs = nvti.get_nvt_refs(vt_id)
            _custom = nvti.get_nvt_metadata(vt_id)
            _name = _custom.pop('name')
            _vt_creation_time = _custom.pop('creation_date')
            _vt_modification_time = _custom.pop('last_modification')

            _summary=None
            _impact=None
            _affected=None
            _insight=None
            _solution=None
            _solution_t=None
            _vuldetect=None
            _qod_t=None
            _qod_v=None

            if 'summary' in _custom:
                _summary  = _custom.pop('summary')
            if 'impact' in _custom:
                _impact   = _custom.pop('impact')
            if 'affected' in _custom:
                _affected = _custom.pop('affected')
            if 'insight' in _custom :
                _insight  = _custom.pop('insight')
            if 'solution' in _custom:
                _solution  = _custom.pop('solution')
                if 'solution_type' in _custom:
                    _solution_t  = _custom.pop('solution_type')

            if 'vuldetect' in _custom:
                _vuldetect  = _custom.pop('vuldetect')
            if 'qod_type' in _custom:
                _qod_t  = _custom.pop('qod_type')
            elif 'qod' in _custom:
                _qod_v  = _custom.pop('qod')

            _severity = dict()
            if 'severity_base_vector' in _custom:
                _severity_vector = _custom.pop('severity_base_vector')
            else:
                _severity_vector = _custom.pop('cvss_base_vector')
            _severity['severity_base_vector'] = _severity_vector
            if 'severity_type' in _custom:
                _severity_type = custom.pop('severity_type')
            else:
                _severity_type = 'cvss_base_v2'
            _severity['severity_type'] = _severity_type
            if 'severity_origin' in _custom:
                _severity['severity_origin'] = _custom.pop('severity_origin')

            _vt_dependencies = list()
            if 'dependencies' in _custom:
                _deps = _custom.pop('dependencies')
                _deps_list = _deps.split(', ')
                for dep in _deps_list:
                    _vt_dependencies.append(oids.get('filename:' + dep))

            ret = self.add_vt(
                vt_id,
                name=_name,
                vt_params=_vt_params,
                vt_refs=_vt_refs,
                custom=_custom,
                vt_creation_time=_vt_creation_time,
                vt_modification_time=_vt_modification_time,
                vt_dependencies=_vt_dependencies,
                summary=_summary,
                impact=_impact,
                affected=_affected,
                insight=_insight,
                solution=_solution,
                solution_t=_solution_t,
                detection=_vuldetect,
                qod_t=_qod_t,
                qod_v=_qod_v,
                severities=_severity
            )
            if ret == -1:
                logger.info("Dupplicated VT with OID: {0}".format(vt_id))
            if ret == -2:
                logger.info("{0}: Invalid OID.".format(vt_id))

        _feed_version = nvti.get_feed_version()
        self.set_feed_version(feed_version=_feed_version)
        PENDING_FEED = False
        logger.debug('Finish loading up vts.')

    @staticmethod
    def get_custom_vt_as_xml_str(vt_id, custom):
        """ Return an xml element with custom metadata formatted as string."""

        nvt = Element('vt')
        for key, val in custom.items():
            xml_key = SubElement(nvt, key)
            xml_key.text = val

        itera = nvt.iter()
        metadata = ''
        for elem in itera:
            if elem.tag != 'vt':
                metadata += (tostring(elem).decode('utf-8'))
        return metadata

    @staticmethod
    def get_severities_vt_as_xml_str(vt_id, severities):
        """ Return an xml element with severities as string."""

        _severity = Element('severity')
        if 'severity_base_vector' in severities:
            _severity.text = severities.pop('severity_base_vector')
        if 'severity_origin' in severities:
            _severity.set('origin', severities.pop('severity_origin'))
        if 'severity_type' in severities:
            _severity.set('type', severities.pop('severity_type'))

        return tostring(_severity).decode('utf-8')

    @staticmethod
    def get_params_vt_as_xml_str(vt_id, vt_params):
        """ Return an xml element with params formatted as string."""
        vt_params_xml = Element('vt_params')
        for prefs in vt_params.items():
            vt_param = Element('vt_param')
            vt_param.set('type', prefs[1]['type'])
            vt_param.set('id', prefs[0])
            xml_name = SubElement(vt_param, 'name')
            xml_name.text = prefs[1]['name']
            if prefs[1]['default']:
                xml_def = SubElement(vt_param, 'default')
                xml_def.text = prefs[1]['default']
            vt_params_xml.append(vt_param)

        params_list = vt_params_xml.findall("vt_param")
        params = ''
        for param in params_list:
            params += (tostring(param).decode('utf-8'))
        return params

    @staticmethod
    def get_refs_vt_as_xml_str(vt_id, vt_refs):
        """ Return an xml element with references formatted as string."""
        vt_refs_xml = Element('vt_refs')
        for ref_type, ref_values in vt_refs.items():
            for value in ref_values:
                vt_ref = Element('ref')
                if ref_type == "xref" and value:
                    for xref in value.split(', '):
                        try:
                            _type, _id = xref.split(':', 1)
                        except ValueError:
                            logger.error(
                                'Not possible to parse xref %s for vt %s' % (
                                    xref, vt_id))
                            continue
                        vt_ref.set('type', _type.lower())
                        vt_ref.set('id', _id)
                elif value:
                    vt_ref.set('type', ref_type.lower())
                    vt_ref.set('id', value)
                else:
                    continue
                vt_refs_xml.append(vt_ref)

        refs_list = vt_refs_xml.findall("ref")
        refs = ''
        for ref in refs_list:
            refs += (tostring(ref).decode('utf-8'))
        return refs

    @staticmethod
    def get_dependencies_vt_as_xml_str(vt_id, dep_list):
        """ Return  an xml element with dependencies as string."""
        vt_deps_xml = Element('vt_deps')
        for dep in dep_list:
            _vt_dep = Element('dependency')
            try:
                _vt_dep.set('vt_id', dep)
            except TypeError:
                logger.error('Not possible to add dependency %s for vt %s' % (
                    dep, vt_id))
                continue
            vt_deps_xml.append(_vt_dep)

        _deps_list = vt_deps_xml.findall("dependency")
        deps = ''
        for _dep in _deps_list:
            deps += (tostring(_dep).decode('utf-8'))
        return deps

    @staticmethod
    def get_creation_time_vt_as_xml_str(vt_id, creation_time):
        """ Return creation time as string."""
        return creation_time

    @staticmethod
    def get_modification_time_vt_as_xml_str(vt_id, modification_time):
        """ Return modification time as string."""
        return modification_time

    @staticmethod
    def get_summary_vt_as_xml_str(vt_id, summary):
        """ Return summary as string."""
        _summary = Element('summary')
        _summary.text = summary
        return tostring(_summary).decode('utf-8')

    @staticmethod
    def get_impact_vt_as_xml_str(vt_id, impact):
        """ Return impact as string."""
        _impact = Element('impact')
        _impact.text = impact
        return tostring(_impact).decode('utf-8')

    @staticmethod
    def get_affected_vt_as_xml_str(vt_id, affected):
        """ Return affected as string."""
        _affected = Element('affected')
        _affected.text = affected
        return tostring(_affected).decode('utf-8')

    @staticmethod
    def get_insight_vt_as_xml_str(vt_id, insight):
        """ Return insight as string."""
        _insight = Element('insight')
        _insight.text = insight
        return tostring(_insight).decode('utf-8')

    @staticmethod
    def get_solution_vt_as_xml_str(vt_id, solution, solution_type=None):
        """ Return solution as string."""
        _solution = Element('solution')
        _solution.text = solution
        if solution_type:
            _solution.set('type', solution_type)
        return tostring(_solution).decode('utf-8')

    @staticmethod
    def get_detection_vt_as_xml_str(vt_id, vuldetect=None, qod_type=None, qod=None):
        """ Return detection as string."""
        _detection = Element('detection')
        if vuldetect:
            _detection.text = vuldetect
        if qod_type:
            _detection.set('qod_type', qod_type)
        elif qod:
            _detection.set('qod', qod)

        return tostring(_detection).decode('utf-8')

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
        if float(prog[1]) == 0:
            return
        host_prog = (float(prog[0]) / float(prog[1])) * 100
        host_progress_dict[target] = host_prog
        total_host = len(target_str_to_list(target))
        self.set_scan_target_progress(scan_id, target,
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
        ctx = openvas_db.db_find(nvti.NVTICACHE_STR)
        while res:
            msg = res.split('|||')
            host_aux = openvas_db.item_get_single('internal/ip')
            roid = msg[3]

            rqod = ''
            if self.vts[roid].get('qod_type'):
                qod_t = self.vts[roid].get('qod_type')
                rqod = nvti.QoD_TYPES[qod_t]
            elif self.vts[roid].get('qod'):
                rqod = self.vts[roid].get('qod')

            rseverity = self.vts[roid]['severities'].get('cvss_base')
            rname = self.vts[roid].get('name')

            if msg[0] == 'ERRMSG':
                self.add_scan_error(scan_id, host=host_aux,
                                    name=rname, value=msg[4], port=msg[2])
            if msg[0] == 'LOG':
                self.add_scan_log(scan_id, host=host_aux, name=rname,
                                  value=msg[4], port=msg[2], qod=rqod,
                                  test_id=roid)
            if msg[0] == 'HOST_DETAIL':
                self.add_scan_log(scan_id, host=host_aux, name=rname,
                                  value=msg[4])
            if msg[0] == 'ALARM':
                self.add_scan_alarm(scan_id, host=host_aux, name=rname,
                                    value=msg[4], port=msg[2],
                                    test_id=roid, severity=rseverity,
                                    qod=rqod)
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
        """ Check if the parent process has received the stop_scan order.
        @in scan_id: ID to identify the scan to be stopped.
        @return 1 if yes, None in other case.
        """
        ctx = openvas_db.kb_connect(dbnum=MAIN_KBINDEX)
        openvas_db.set_global_redisctx(ctx)
        status = openvas_db.item_get_single(('internal/%s' % scan_id))
        return status == 'stop_all'

    @staticmethod
    def stop_scan(global_scan_id):
        """ Set a key in redis to indicate the wrapper is stopped.
        It is done through redis because it is a new multiprocess
        instance and it is not possible to reach the variables
        of the grandchild process. Send SIGUSR2 to openvas to stop
        each running scan."""
        ctx = openvas_db.kb_connect()
        for current_kbi in range(0, openvas_db.MAX_DBINDEX):
            ctx.execute_command('SELECT '+ str(current_kbi))
            openvas_db.set_global_redisctx(ctx)
            scan_id = openvas_db.item_get_single(
                ('internal/%s/globalscanid' % global_scan_id))
            if scan_id:
                openvas_db.item_set_single(('internal/%s' % scan_id),
                                           ['stop_all', ])
                ovas_pid = openvas_db.item_get_single('internal/ovas_pid')
                parent = psutil.Process(int(ovas_pid))
                openvas_db.release_db(current_kbi)
                parent.send_signal(signal.SIGUSR2)
                logger.debug('Stopping process: {0}'.format(parent))

    def get_vts_in_groups(self, ctx, filters):
        """ Return a list of vts which match with the given filter.

        @input filters A list of filters. Each filter has key, operator and
                       a value. They are separated by a space.
                       Supported keys: family
        @return Return a list of vts which match with the given filter.
        """
        vts_list = list()
        families = dict()
        oids = nvti.get_oids()
        for filename, oid in oids:
            family = self.vts[oid]['custom'].get('family')
            if family not in families:
                families[family] = list()
            families[family].append(oid)

        for elem in filters:
            key, value = elem.split('=')
            if key == 'family' and value in families:
                vts_list.extend(families[value])
        return vts_list

    def get_vt_param_type(self, vtid, vt_param_id):
        """ Return the type of the vt parameter from the vts dictionary. """
        vt_params_list = self.vts[vtid].get("vt_params")
        return vt_params_list[vt_param_id]["type"]

    @staticmethod
    def check_param_type(vt_param_value, param_type):
        """ Check if the value of a vt parameter matches with
        the type founded.
        """
        if (param_type in ['entry',
                           'file',
                           'password',
                           'radio',
                           'sshlogin', ] and isinstance(vt_param_value, str)):
            return None
        elif (param_type == 'checkbox' and
              (vt_param_value == 'yes' or vt_param_value == 'no')):
            return None
        elif param_type == 'integer':
            try:
                int(vt_param_value)
            except ValueError:
                return 1
            return None

        return 1

    def process_vts(self, vts):
        """ Add single VTs and their parameters. """
        vts_list = []
        vts_params = []
        vtgroups = vts.pop('vt_groups')

        ctx = openvas_db.db_find(nvti.NVTICACHE_STR)
        openvas_db.set_global_redisctx(ctx)
        if vtgroups:
            vts_list = self.get_vts_in_groups(ctx, vtgroups)

        for vtid, vt_params in vts.items():
            vts_list.append(vtid)
            nvt_name = self.vts[vtid].get('name')
            for vt_param_id, vt_param_value in vt_params.items():
                param_type = self.get_vt_param_type(vtid, vt_param_id)
                if vt_param_id == 'timeout':
                    type_aux = 'integer'
                else:
                    type_aux = param_type
                if self.check_param_type(vt_param_value, type_aux):
                    logger.debug('Expected {} type for parameter value {}'
                                 .format(type_aux, str(vt_param_value)))
                param = ["{0}[{1}]:{2}".format(nvt_name, param_type,
                                               vt_param_id),
                         str(vt_param_value)]
                vts_params.append(param)
        return vts_list, vts_params

    @staticmethod
    def build_credentials_as_prefs(credentials):
        """ Parse the credential dictionary.
        @param credentials: Dictionary with the credentials.

        @return A list with the credentials in string format to be
                added to the redis KB.
        """
        cred_prefs_list = []
        for credential in credentials.items():
            service = credential[0]
            cred_params = credentials.get(service)
            cred_type = cred_params.get('type', '')
            username = cred_params.get('username', '')
            password = cred_params.get('password', '')

            if service == 'ssh':
                port = cred_params.get('port', '')
                cred_prefs_list.append('auth_port_ssh|||' +
                                       '{0}'.format(port))
                cred_prefs_list.append('SSH Authorization[entry]:SSH login ' +
                                       'name:|||{0}'.format(username))
                if cred_type == 'up':
                    cred_prefs_list.append('SSH Authorization[password]:' +
                                           'SSH password (unsafe!):|||' +
                                           '{0}'.format(password))
                else:
                    private = cred_params.get('private', '')
                    cred_prefs_list.append('SSH Authorization[password]:' +
                                           'SSH key passphrase:|||' +
                                           '{0}'.format(password))
                    cred_prefs_list.append('SSH Authorization[file]:' +
                                           'SSH private key:|||' +
                                           '{0}'.format(private))
            if service == 'smb':
                cred_prefs_list.append('SMB Authorization[entry]:SMB login:' +
                                       '|||{0}'.format(username))
                cred_prefs_list.append('SMB Authorization[password]:' +
                                       'SMB password :|||' +
                                       '{0}'.format(password))
            if service == 'esxi':
                cred_prefs_list.append('ESXi Authorization[entry]:ESXi login ' +
                                       'name:|||{0}'.format(username))
                cred_prefs_list.append('ESXi Authorization[password]:' +
                                       'ESXi login password:|||' +
                                       '{0}'.format(password))

            if service == 'snmp':
                community = cred_params.get('community', '')
                auth_algorithm = cred_params.get('auth_algorithm', '')
                privacy_password = cred_params.get('privacy_password', '')
                privacy_algorithm = cred_params.get('privacy_algorithm', '')

                cred_prefs_list.append('SNMP Authorization[password]:' +
                                       'SNMP Community:' +
                                       '{0}'.format(community))
                cred_prefs_list.append('SNMP Authorization[entry]:' +
                                       'SNMPv3 Username:' +
                                       '{0}'.format(username))
                cred_prefs_list.append('SNMP Authorization[password]:' +
                                       'SNMPv3 Password:' +
                                       '{0}'.format(password))
                cred_prefs_list.append('SNMP Authorization[radio]:' +
                                       'SNMPv3 Authentication Algorithm:' +
                                       '{0}'.format(auth_algorithm))
                cred_prefs_list.append('SNMP Authorization[password]:' +
                                       'SNMPv3 Privacy Password:' +
                                       '{0}'.format(privacy_password))
                cred_prefs_list.append('SNMP Authorization[radio]:' +
                                       'SNMPv3 Privacy Algorithm:' +
                                       '{0}'.format(privacy_algorithm))

        return cred_prefs_list

    def exec_scan(self, scan_id, target):
        """ Starts the OpenVAS scanner for scan_id scan. """
        if PENDING_FEED:
            logger.info(
                '%s: There is a pending feed update. '
                'The scan can not be started.' % scan_id)
            self.add_scan_error(
                scan_id, name='', host=target,
                value=('It was not possible to start the scan,'
                'because a pending feed update. Please try later'))
            return 2

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

        # To avoid interference between scan process during a parallel scanning
        # new uuid is used internally for each scan.
        openvas_scan_id = str(uuid.uuid4())
        openvas_db.item_add_single(('internal/%s' % openvas_scan_id), ['new', ])
        openvas_db.item_add_single(('internal/%s/globalscanid' % scan_id), [openvas_scan_id, ])

        # Set scan preferences
        for item in options.items():
            item_type = ''
            if item[0] in OSPD_PARAMS:
                item_type = OSPD_PARAMS[item[0]].get('type')
            if item_type == 'boolean' and item[1] == 1:
                val = 'yes'
            else:
                val = str(item[1])
            prefs_val.append(item[0] + "|||" + val)
        openvas_db.item_add_single(str('internal/%s/scanprefs' % (openvas_scan_id)),
                                   prefs_val)

        # Store MAIN_KBINDEX as global preference
        ov_maindbid = ('ov_maindbid|||%d' % MAIN_KBINDEX)
        openvas_db.item_add_single(('internal/%s/scanprefs' % openvas_scan_id),
                                   [ov_maindbid, ])

        # Set target
        target_aux = ('TARGET|||%s' % target)
        openvas_db.item_add_single(('internal/%s/scanprefs' % openvas_scan_id),
                                   [target_aux, ])
        # Set port range
        port_range = ('port_range|||%s' % ports)
        openvas_db.item_add_single(('internal/%s/scanprefs' % openvas_scan_id),
                                   [port_range, ])

        # Set credentials
        credentials = self.get_scan_credentials(scan_id, target)
        if credentials:
            cred_prefs = self.build_credentials_as_prefs(credentials)
            openvas_db.item_add_single(str('internal/%s/scanprefs' % openvas_scan_id),
                                       cred_prefs)

        # Set plugins to run
        nvts = self.get_scan_vts(scan_id)
        if nvts != '':
            nvts_list, nvts_params = self.process_vts(nvts)
            # Select the scan KB again.
            ctx.execute_command('SELECT '+ str(MAIN_KBINDEX))
            openvas_db.set_global_redisctx(ctx)
            # Add nvts list
            separ = ';'
            plugin_list = ('plugin_set|||%s' % separ.join(nvts_list))
            openvas_db.item_add_single(('internal/%s/scanprefs' % openvas_scan_id),
                                       [plugin_list, ])
            # Add nvts parameters
            for elem in nvts_params:
                item = ('%s|||%s' % (elem[0], elem[1]))
                openvas_db.item_add_single(('internal/%s/scanprefs' % openvas_scan_id),
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

        cmd = ['openvassd', '--scan-start', openvas_scan_id]
        try:
            result = subprocess.Popen(cmd, shell=False)
        except OSError:
            # the command is not available
            return False

        ovas_pid = result.pid
        logger.debug('pid = {0}'.format(ovas_pid))
        openvas_db.item_add_single(('internal/ovas_pid'), [ovas_pid, ])

        # Wait until the scanner starts and loads all the preferences.
        while openvas_db.item_get_single('internal/'+ openvas_scan_id) == 'new':
            time.sleep(1)

        no_id_found = False
        while True:
            time.sleep(3)

            # Check if the client stopped the whole scan
            if self.scan_is_stopped(openvas_scan_id):
                return 1

            ctx = openvas_db.kb_connect(MAIN_KBINDEX)
            openvas_db.set_global_redisctx(ctx)
            dbs = openvas_db.item_get_set('internal/dbindex')
            for i in list(dbs):
                if i == MAIN_KBINDEX:
                    continue
                ctx.execute_command('SELECT '+ str(i))
                openvas_db.set_global_redisctx(ctx)
                id_aux = ctx.execute_command('srandmember internal/scan_id')
                if not id_aux:
                    continue
                if id_aux == openvas_scan_id:
                    no_id_found = False
                    self.get_openvas_timestamp_scan_host(scan_id, target)
                    self.get_openvas_result(scan_id)
                    self.get_openvas_status(scan_id, target)
                    if self.scan_is_finished(openvas_scan_id):
                        ctx.execute_command('SELECT '+ str(MAIN_KBINDEX))
                        openvas_db.remove_set_member('internal/dbindex', i)
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
