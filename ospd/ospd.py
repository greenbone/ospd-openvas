# Copyright (C) 2014-2018 Greenbone Networks GmbH
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

# pylint: disable=too-many-lines

""" OSP Daemon core class.
"""


# This is needed for older pythons as our current module is called the same
# as the package we are in ...
# Another solution would be to rename that file.
from __future__ import absolute_import

import logging
import socket
import ssl
import multiprocessing
import re
import time
import os
import subprocess

from xml.etree.ElementTree import Element, SubElement

import defusedxml.ElementTree as secET

from ospd import __version__
from ospd.errors import OspdCommandError, OspdError
from ospd.misc import ScanCollection, ResultType, ScanStatus, valid_uuid
from ospd.network import resolve_hostname, target_str_to_list
from ospd.server import BaseServer
from ospd.vtfilter import VtsFilter
from ospd.xml import simple_response_str, get_result_xml

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "1.2"

SCHEDULER_CHECK_PERIOD = 5  # in seconds

GVMCG_TITLES = [
    'cpu-*',
    'proc',
    'mem',
    'swap',
    'load',
    'df-*',
    'disk-sd[a-z][0-9]-rw',
    'disk-sd[a-z][0-9]-load',
    'disk-sd[a-z][0-9]-io-load',
    'interface-eth*-traffic',
    'interface-eth*-err-rate',
    'interface-eth*-err',
    'sensors-*_temperature-*',
    'sensors-*_fanspeed-*',
    'sensors-*_voltage-*',
    'titles',
]

BASE_SCANNER_PARAMS = {
    'debug_mode': {
        'type': 'boolean',
        'name': 'Debug Mode',
        'default': 0,
        'mandatory': 0,
        'description': 'Whether to get extra scan debug information.',
    },
    'dry_run': {
        'type': 'boolean',
        'name': 'Dry Run',
        'default': 0,
        'mandatory': 0,
        'description': 'Whether to dry run scan.',
    },
}

COMMANDS_TABLE = {
    'start_scan': {
        'description': 'Start a new scan.',
        'attributes': {
            'target': 'Target host to scan',
            'ports': 'Ports list to scan',
            'scan_id': 'Optional UUID value to use as scan ID',
            'parallel': 'Optional nummer of parallel target to scan',
        },
        'elements': None,
    },
    'stop_scan': {
        'description': 'Stop a currently running scan.',
        'attributes': {'scan_id': 'ID of scan to stop.'},
        'elements': None,
    },
    'help': {
        'description': 'Print the commands help.',
        'attributes': {'format': 'Help format. Could be text or xml.'},
        'elements': None,
    },
    'get_scans': {
        'description': 'List the scans in buffer.',
        'attributes': {
            'scan_id': 'ID of a specific scan to get.',
            'details': 'Whether to return the full scan report.',
        },
        'elements': None,
    },
    'get_vts': {
        'description': 'List of available vulnerability tests.',
        'attributes': {
            'vt_id': 'ID of a specific vulnerability test to get.',
            'filter': 'Optional filter to get an specific vt collection.',
        },
        'elements': None,
    },
    'delete_scan': {
        'description': 'Delete a finished scan.',
        'attributes': {'scan_id': 'ID of scan to delete.'},
        'elements': None,
    },
    'get_version': {
        'description': 'Return various versions.',
        'attributes': None,
        'elements': None,
    },
    'get_scanner_details': {
        'description': 'Return scanner description and parameters',
        'attributes': None,
        'elements': None,
    },
    'get_performance': {
        'description': 'Return system report',
        'attributes': {
            'start': 'Time of first data point in report.',
            'end': 'Time of last data point in report.',
            'title': 'Name of report.',
        },
        'elements': None,
    },
}


class OSPDaemon:

    """ Daemon class for OSP traffic handling.

    Every scanner wrapper should subclass it and make necessary additions and
    changes.

    * Add any needed parameters in __init__.
    * Implement check() method which verifies scanner availability and other
      environment related conditions.
    * Implement process_scan_params and exec_scan methods which are
      specific to handling the <start_scan> command, executing the wrapped
      scanner and storing the results.
    * exec_scan() should return 0 if host is dead or not reached, 1 if host is
      alive and 2 if scan error or status is unknown.
    * Implement other methods that assert to False such as get_scanner_name,
      get_scanner_version.
    * Use Call set_command_attributes at init time to add scanner command
      specific options eg. the w3af profile for w3af wrapper.
    """

    def __init__(
        self, *, customvtfilter=None, **kwargs
    ):  # pylint: disable=unused-argument
        """ Initializes the daemon's internal data. """
        self.scan_collection = ScanCollection()
        self.scan_processes = dict()

        self.daemon_info = dict()
        self.daemon_info['name'] = "OSPd"
        self.daemon_info['version'] = __version__
        self.daemon_info['description'] = "No description"

        self.scanner_info = dict()
        self.scanner_info['name'] = 'No name'
        self.scanner_info['version'] = 'No version'
        self.scanner_info['description'] = 'No description'

        self.server_version = None  # Set by the subclass.

        self.protocol_version = PROTOCOL_VERSION

        self.commands = COMMANDS_TABLE

        self.scanner_params = dict()

        for name, param in BASE_SCANNER_PARAMS.items():
            self.add_scanner_param(name, param)

        self.vts = dict()
        self.vt_id_pattern = re.compile("[0-9a-zA-Z_\\-:.]{1,80}")
        self.vts_version = None

        if customvtfilter:
            self.vts_filter = customvtfilter
        else:
            self.vts_filter = VtsFilter()

    def init(self):
        """ Should be overridden by a subclass if the initialization is costly.

            Will be called before check.
        """

    def set_command_attributes(self, name, attributes):
        """ Sets the xml attributes of a specified command. """
        if self.command_exists(name):
            command = self.commands.get(name)
            command['attributes'] = attributes

    def add_scanner_param(self, name, scanner_param):
        """ Add a scanner parameter. """

        assert name
        assert scanner_param
        self.scanner_params[name] = scanner_param
        command = self.commands.get('start_scan')
        command['elements'] = {
            'scanner_params': {
                k: v['name'] for k, v in self.scanner_params.items()
            }
        }

    def add_vt(
        self,
        vt_id,
        name=None,
        vt_params=None,
        vt_refs=None,
        custom=None,
        vt_creation_time=None,
        vt_modification_time=None,
        vt_dependencies=None,
        summary=None,
        impact=None,
        affected=None,
        insight=None,
        solution=None,
        solution_t=None,
        detection=None,
        qod_t=None,
        qod_v=None,
        severities=None,
    ):
        """ Add a vulnerability test information.
        """

        if not vt_id:
            raise OspdError('Invalid vt_id {}'.format(vt_id))

        if self.vt_id_pattern.fullmatch(vt_id) is None:
            raise OspdError('Invalid vt_id {}'.format(vt_id))

        if vt_id in self.vts:
            raise OspdError('vt_id {} already exists'.format(vt_id))

        if name is None:
            name = ''

        vt = {'name': name}
        if custom is not None:
            vt["custom"] = custom
        if vt_params is not None:
            vt["vt_params"] = vt_params
        if vt_refs is not None:
            vt["vt_refs"] = vt_refs
        if vt_dependencies is not None:
            vt["vt_dependencies"] = vt_dependencies
        if vt_creation_time is not None:
            vt["creation_time"] = vt_creation_time
        if vt_modification_time is not None:
            vt["modification_time"] = vt_modification_time
        if summary is not None:
            vt["summary"] = summary
        if impact is not None:
            vt["impact"] = impact
        if affected is not None:
            vt["affected"] = affected
        if insight is not None:
            vt["insight"] = insight

        if solution is not None:
            vt["solution"] = solution
            if solution_t is not None:
                vt["solution_type"] = solution_t

        if detection is not None:
            vt["detection"] = detection

        if qod_t is not None:
            vt["qod_type"] = qod_t
        elif qod_v is not None:
            vt["qod"] = qod_v

        if severities is not None:
            vt["severities"] = severities

        self.vts[vt_id] = vt

    def set_vts_version(self, vts_version):
        """ Add into the vts dictionary an entry to identify the
        vts version.

        Parameters:
            vts_version (str): Identifies a unique vts version.
        """
        if not vts_version:
            raise OspdCommandError(
                'A vts_version parameter is required', 'set_vts_version'
            )
        self.vts_version = vts_version

    def get_vts_version(self):
        """Return the vts version.
        """
        return self.vts_version

    def command_exists(self, name):
        """ Checks if a commands exists. """
        return name in self.commands.keys()

    def get_scanner_name(self):
        """ Gives the wrapped scanner's name. """
        return self.scanner_info['name']

    def get_scanner_version(self):
        """ Gives the wrapped scanner's version. """
        return self.scanner_info['version']

    def get_scanner_description(self):
        """ Gives the wrapped scanner's description. """
        return self.scanner_info['description']

    def get_server_version(self):
        """ Gives the specific OSP server's version. """
        assert self.server_version
        return self.server_version

    def get_protocol_version(self):
        """ Gives the OSP's version. """
        return self.protocol_version

    def _preprocess_scan_params(self, xml_params):
        """ Processes the scan parameters. """
        params = {}
        for param in xml_params:
            params[param.tag] = param.text or ''
        # Set default values.
        for key in self.scanner_params:
            if key not in params:
                params[key] = self.get_scanner_param_default(key)
                if self.get_scanner_param_type(key) == 'selection':
                    params[key] = params[key].split('|')[0]
        # Validate values.
        for key in params:
            param_type = self.get_scanner_param_type(key)
            if not param_type:
                continue
            if param_type in ['integer', 'boolean']:
                try:
                    params[key] = int(params[key])
                except ValueError:
                    raise OspdCommandError(
                        'Invalid %s value' % key, 'start_scan'
                    )
            if param_type == 'boolean':
                if params[key] not in [0, 1]:
                    raise OspdCommandError(
                        'Invalid %s value' % key, 'start_scan'
                    )
            elif param_type == 'selection':
                selection = self.get_scanner_param_default(key).split('|')
                if params[key] not in selection:
                    raise OspdCommandError(
                        'Invalid %s value' % key, 'start_scan'
                    )
            if self.get_scanner_param_mandatory(key) and params[key] == '':
                raise OspdCommandError(
                    'Mandatory %s value is missing' % key, 'start_scan'
                )
        return params

    def process_scan_params(self, params):
        """ This method is to be overridden by the child classes if necessary
        """
        return params

    def process_vts_params(self, scanner_vts):
        """ Receive an XML object with the Vulnerability Tests an their
        parameters to be use in a scan and return a dictionary.

        @param: XML element with vt subelements. Each vt has an
                id attribute. Optional parameters can be included
                as vt child.
                Example form:
                <vt_selection>
                  <vt_single id='vt1' />
                  <vt_single id='vt2'>
                    <vt_value id='param1'>value</vt_value>
                  </vt_single>
                  <vt_group filter='family=debian'/>
                  <vt_group filter='family=general'/>
                </vt_selection>

        @return: Dictionary containing the vts attribute and subelements,
                 like the VT's id and VT's parameters.
                 Example form:
                 {'vt1': {},
                  'vt2': {'value_id': 'value'},
                  'vt_groups': ['family=debian', 'family=general']}
        """
        vt_selection = {}
        filters = list()
        for vt in scanner_vts:
            if vt.tag == 'vt_single':
                vt_id = vt.attrib.get('id')
                vt_selection[vt_id] = {}
                for vt_value in vt:
                    if not vt_value.attrib.get('id'):
                        raise OspdCommandError(
                            'Invalid VT preference. No attribute id',
                            'start_scan',
                        )
                    vt_value_id = vt_value.attrib.get('id')
                    vt_value_value = vt_value.text if vt_value.text else ''
                    vt_selection[vt_id][vt_value_id] = vt_value_value
            if vt.tag == 'vt_group':
                vts_filter = vt.attrib.get('filter', None)
                if vts_filter is None:
                    raise OspdCommandError(
                        'Invalid VT group. No filter given.', 'start_scan'
                    )
                filters.append(vts_filter)
        vt_selection['vt_groups'] = filters
        return vt_selection

    @staticmethod
    def process_credentials_elements(cred_tree):
        """ Receive an XML object with the credentials to run
        a scan against a given target.

        @param:
        <credentials>
          <credential type="up" service="ssh" port="22">
            <username>scanuser</username>
            <password>mypass</password>
          </credential>
          <credential type="up" service="smb">
            <username>smbuser</username>
            <password>mypass</password>
          </credential>
        </credentials>

        @return: Dictionary containing the credentials for a given target.
                 Example form:
                 {'ssh': {'type': type,
                          'port': port,
                          'username': username,
                          'password': pass,
                        },
                  'smb': {'type': type,
                          'username': username,
                          'password': pass,
                         },
                   }
        """
        credentials = {}
        for credential in cred_tree:
            service = credential.attrib.get('service')
            credentials[service] = {}
            credentials[service]['type'] = credential.attrib.get('type')
            if service == 'ssh':
                credentials[service]['port'] = credential.attrib.get('port')
            for param in credential:
                credentials[service][param.tag] = param.text

        return credentials

    @classmethod
    def process_targets_element(cls, scanner_target):
        """ Receive an XML object with the target, ports and credentials to run
        a scan against.

        @param: XML element with target subelements. Each target has <hosts>
        and <ports> subelements. Hosts can be a single host, a host range,
        a comma-separated host list or a network address.
        <ports> and  <credentials> are optional. Therefore each ospd-scanner
        should check for a valid ones if needed.

                Example form:
                <targets>
                  <target>
                    <hosts>localhosts</hosts>
                    <exclude_hosts>localhost1</exclude_hosts>
                    <ports>80,443</ports>
                  </target>
                  <target>
                    <hosts>192.168.0.0/24</hosts>
                    <ports>22</ports>
                    <credentials>
                      <credential type="up" service="ssh" port="22">
                        <username>scanuser</username>
                        <password>mypass</password>
                      </credential>
                      <credential type="up" service="smb">
                        <username>smbuser</username>
                        <password>mypass</password>
                      </credential>
                    </credentials>
                  </target>
                </targets>

        @return: A list of [hosts, port, {credentials}, exclude_hosts] list.
                 Example form:
                 [['localhosts', '80,43', '', 'localhosts1'],
                  ['192.168.0.0/24', '22', {'smb': {'type': type,
                                                    'port': port,
                                                    'username': username,
                                                    'password': pass,
                                                   }}], '']
        """

        target_list = []
        for target in scanner_target:
            exclude_hosts = ''
            ports = ''
            credentials = {}
            for child in target:
                if child.tag == 'hosts':
                    hosts = child.text
                if child.tag == 'exclude_hosts':
                    exclude_hosts = child.text
                if child.tag == 'ports':
                    ports = child.text
                if child.tag == 'credentials':
                    credentials = cls.process_credentials_elements(child)
            if hosts:
                target_list.append([hosts, ports, credentials, exclude_hosts])
            else:
                raise OspdCommandError('No target to scan', 'start_scan')

        return target_list

    def handle_start_scan_command(self, scan_et):
        """ Handles <start_scan> command.

        @return: Response string for <start_scan> command.
        """

        target_str = scan_et.attrib.get('target')
        ports_str = scan_et.attrib.get('ports')
        # For backward compatibility, if target and ports attributes are set,
        # <targets> element is ignored.
        if target_str is None or ports_str is None:
            target_list = scan_et.find('targets')
            if target_list is None or len(target_list) == 0:
                raise OspdCommandError('No targets or ports', 'start_scan')
            else:
                scan_targets = self.process_targets_element(target_list)
        else:
            scan_targets = []
            for single_target in target_str_to_list(target_str):
                scan_targets.append([single_target, ports_str, '', ''])

        scan_id = scan_et.attrib.get('scan_id')
        if scan_id is not None and scan_id != '' and not valid_uuid(scan_id):
            raise OspdCommandError('Invalid scan_id UUID', 'start_scan')

        try:
            parallel = int(scan_et.attrib.get('parallel', '1'))
            if parallel < 1 or parallel > 20:
                parallel = 1
        except ValueError:
            raise OspdCommandError(
                'Invalid value for parallel scans. ' 'It must be a number',
                'start_scan',
            )

        scanner_params = scan_et.find('scanner_params')
        if scanner_params is None:
            raise OspdCommandError('No scanner_params element', 'start_scan')

        params = self._preprocess_scan_params(scanner_params)

        # VTS is an optional element. If present should not be empty.
        vt_selection = {}
        scanner_vts = scan_et.find('vt_selection')
        if scanner_vts is not None:
            if len(scanner_vts) == 0:
                raise OspdCommandError('VTs list is empty', 'start_scan')
            else:
                vt_selection = self.process_vts_params(scanner_vts)

        # Dry run case.
        if 'dry_run' in params and int(params['dry_run']):
            scan_func = self.dry_run_scan
            scan_params = None
        else:
            scan_func = self.start_scan
            scan_params = self.process_scan_params(params)

        scan_id = self.create_scan(
            scan_id, scan_targets, scan_params, vt_selection
        )
        scan_process = multiprocessing.Process(
            target=scan_func, args=(scan_id, scan_targets, parallel)
        )
        self.scan_processes[scan_id] = scan_process
        scan_process.start()
        id_ = Element('id')
        id_.text = scan_id
        return simple_response_str('start_scan', 200, 'OK', id_)

    def handle_stop_scan_command(self, scan_et):
        """ Handles <stop_scan> command.

        @return: Response string for <stop_scan> command.
        """

        scan_id = scan_et.attrib.get('scan_id')
        if scan_id is None or scan_id == '':
            raise OspdCommandError('No scan_id attribute', 'stop_scan')
        self.stop_scan(scan_id)

        return simple_response_str('stop_scan', 200, 'OK')

    def stop_scan(self, scan_id):
        scan_process = self.scan_processes.get(scan_id)
        if not scan_process:
            raise OspdCommandError(
                'Scan not found {0}.'.format(scan_id), 'stop_scan'
            )
        if not scan_process.is_alive():
            raise OspdCommandError(
                'Scan already stopped or finished.', 'stop_scan'
            )

        self.set_scan_status(scan_id, ScanStatus.STOPPED)
        logger.info('%s: Scan stopping %s.', scan_id, scan_process.ident)
        self.stop_scan_cleanup(scan_id)
        try:
            scan_process.terminate()
        except AttributeError:
            logger.debug('%s: The scanner task stopped unexpectedly.', scan_id)

        os.killpg(os.getpgid(scan_process.ident), 15)
        if scan_process.ident != os.getpid():
            scan_process.join()
        logger.info('%s: Scan stopped.', scan_id)

    @staticmethod
    def stop_scan_cleanup(scan_id):
        """ Should be implemented by subclass in case of a clean up before
        terminating is needed. """

    @staticmethod
    def target_is_finished(scan_id):
        """ Should be implemented by subclass in case of a check before
        stopping is needed. """

    def exec_scan(self, scan_id, target):
        """ Asserts to False. Should be implemented by subclass. """
        raise NotImplementedError

    def finish_scan(self, scan_id):
        """ Sets a scan as finished. """
        self.set_scan_progress(scan_id, 100)
        self.set_scan_status(scan_id, ScanStatus.FINISHED)
        logger.info("%s: Scan finished.", scan_id)

    def get_daemon_name(self):
        """ Gives osp daemon's name. """
        return self.daemon_info['name']

    def get_daemon_version(self):
        """ Gives osp daemon's version. """
        return self.daemon_info['version']

    def get_scanner_param_type(self, param):
        """ Returns type of a scanner parameter. """
        assert isinstance(param, str)
        entry = self.scanner_params.get(param)
        if not entry:
            return None
        return entry.get('type')

    def get_scanner_param_mandatory(self, param):
        """ Returns if a scanner parameter is mandatory. """
        assert isinstance(param, str)
        entry = self.scanner_params.get(param)
        if not entry:
            return False
        return entry.get('mandatory')

    def get_scanner_param_default(self, param):
        """ Returns default value of a scanner parameter. """
        assert isinstance(param, str)
        entry = self.scanner_params.get(param)
        if not entry:
            return None
        return entry.get('default')

    def get_scanner_params_xml(self):
        """ Returns the OSP Daemon's scanner params in xml format. """
        scanner_params = Element('scanner_params')
        for param_id, param in self.scanner_params.items():
            param_xml = SubElement(scanner_params, 'scanner_param')
            for name, value in [('id', param_id), ('type', param['type'])]:
                param_xml.set(name, value)
            for name, value in [
                ('name', param['name']),
                ('description', param['description']),
                ('default', param['default']),
                ('mandatory', param['mandatory']),
            ]:
                elem = SubElement(param_xml, name)
                elem.text = str(value)
        return scanner_params

    def handle_client_stream(self, stream):
        """ Handles stream of data received from client. """

        data = b''

        while True:
            try:
                buf = stream.read()
                if not buf:
                    break

                data += buf
            except (AttributeError, ValueError) as message:
                logger.error(message)
                return
            except (ssl.SSLError) as exception:
                logger.debug('Error: %s', exception)
                break
            except (socket.timeout) as exception:
                break

        if len(data) <= 0:
            logger.debug("Empty client stream")
            return

        try:
            response = self.handle_command(data)
        except OspdCommandError as exception:
            response = exception.as_xml()
            logger.debug('Command error: %s', exception.message)
        except Exception:  # pylint: disable=broad-except
            logger.exception('While handling client command:')
            exception = OspdCommandError('Fatal error', 'error')
            response = exception.as_xml()

        stream.write(response)
        stream.close()

    def parallel_scan(self, scan_id, target):
        """ Starts the scan with scan_id. """
        try:
            ret = self.exec_scan(scan_id, target)
            if ret == 0:
                logger.info("%s: Host scan dead.", target)
            elif ret == 1:
                logger.info("%s: Host scan alived.", target)
            elif ret == 2:
                logger.info("%s: Scan error or status unknown.", target)
            else:
                logger.debug('%s: No host status returned', target)
        except Exception as e:  # pylint: disable=broad-except
            self.add_scan_error(
                scan_id,
                name='',
                host=target,
                value='Host process failure (%s).' % e,
            )
            logger.exception('While scanning %s:', target)
        else:
            logger.info("%s: Host scan finished.", target)

    def check_pending_target(self, scan_id, multiscan_proc):
        """ Check if a scan process is still alive. In case the process
        finished or is stopped, removes the process from the multiscan
        _process list.
        Processes dead and with progress < 100% are considered stopped
        or with failures. Then will try to stop the other runnings (target)
        scans owned by the same task.

        @input scan_id        Scan_id of the whole scan.
        @input multiscan_proc A list with the scan process which
                              may still be alive.

        @return Actualized list with current running scan processes.
        """
        for running_target_proc, running_target_id in multiscan_proc:
            if not running_target_proc.is_alive():
                target_prog = self.get_scan_target_progress(
                    scan_id, running_target_id
                )

                _not_finished_clean = target_prog < 100
                _not_stopped = (
                    self.get_scan_status(scan_id) != ScanStatus.STOPPED
                )

                if _not_finished_clean and _not_stopped:
                    if not self.target_is_finished(scan_id):
                        self.stop_scan(scan_id)

                running_target = (running_target_proc, running_target_id)
                multiscan_proc.remove(running_target)

        return multiscan_proc

    def calculate_progress(self, scan_id):
        """ Calculate the total scan progress from the
        partial target progress. """

        t_prog = dict()
        for target in self.get_scan_target(scan_id):
            t_prog[target] = self.get_scan_target_progress(scan_id, target)
        return sum(t_prog.values()) / len(t_prog)

    def process_exclude_hosts(self, scan_id, target_list):
        """ Process the exclude hosts before launching the scans.
        Set exclude hosts as finished with 100% to calculate
        the scan progress."""

        for target, _, _, exclude_hosts in target_list:
            exc_hosts_list = ''
            if not exclude_hosts:
                continue
            exc_hosts_list = target_str_to_list(exclude_hosts)
            for host in exc_hosts_list:
                self.set_scan_host_finished(scan_id, target, host)
                self.set_scan_host_progress(scan_id, target, host, 100)

    def start_scan(self, scan_id, targets, parallel=1):
        """ Handle N parallel scans if 'parallel' is greater than 1. """

        os.setsid()
        multiscan_proc = []
        logger.info("%s: Scan started.", scan_id)
        target_list = targets
        if target_list is None or not target_list:
            raise OspdCommandError('Erroneous targets list', 'start_scan')

        self.process_exclude_hosts(scan_id, target_list)

        for _index, target in enumerate(target_list):
            while len(multiscan_proc) >= parallel:
                progress = self.calculate_progress(scan_id)
                self.set_scan_progress(scan_id, progress)
                multiscan_proc = self.check_pending_target(
                    scan_id, multiscan_proc
                )
                time.sleep(1)

            # If the scan status is stopped, does not launch anymore target
            # scans
            if self.get_scan_status(scan_id) == ScanStatus.STOPPED:
                return

            logger.info(
                "%s: Host scan started on ports %s.", target[0], target[1]
            )
            scan_process = multiprocessing.Process(
                target=self.parallel_scan, args=(scan_id, target[0])
            )
            multiscan_proc.append((scan_process, target[0]))
            scan_process.start()
            self.set_scan_status(scan_id, ScanStatus.RUNNING)

        # Wait until all single target were scanned
        while multiscan_proc:
            multiscan_proc = self.check_pending_target(scan_id, multiscan_proc)
            if multiscan_proc:
                progress = self.calculate_progress(scan_id)
                self.set_scan_progress(scan_id, progress)
            time.sleep(1)

        # Only set the scan as finished if the scan was not stopped.
        if self.get_scan_status(scan_id) != ScanStatus.STOPPED:
            self.finish_scan(scan_id)

    def dry_run_scan(self, scan_id, targets, parallel):
        """ Dry runs a scan. """

        os.setsid()
        for _, target in enumerate(targets):
            host = resolve_hostname(target[0])
            if host is None:
                logger.info("Couldn't resolve %s.", target[0])
                continue
            port = self.get_scan_ports(scan_id, target=target[0])
            logger.info("%s:%s: Dry run mode.", host, port)
            self.add_scan_log(
                scan_id, name='', host=host, value='Dry run result'
            )
        self.finish_scan(scan_id)

    def handle_timeout(self, scan_id, host):
        """ Handles scanner reaching timeout error. """
        self.add_scan_error(
            scan_id,
            host=host,
            name="Timeout",
            value="{0} exec timeout.".format(self.get_scanner_name()),
        )

    def set_scan_host_finished(self, scan_id, target, host):
        """ Add the host in a list of finished hosts """
        self.scan_collection.set_host_finished(scan_id, target, host)

    def set_scan_progress(self, scan_id, progress):
        """ Sets scan_id scan's progress which is a number
        between 0 and 100. """
        self.scan_collection.set_progress(scan_id, progress)

    def set_scan_host_progress(self, scan_id, target, host, progress):
        """ Sets host's progress which is part of target. """
        self.scan_collection.set_host_progress(
            scan_id, target, host, progress
        )

    def set_scan_status(self, scan_id, status):
        """ Set the scan's status."""
        self.scan_collection.set_status(scan_id, status)

    def get_scan_status(self, scan_id):
        """ Get scan_id scans's status."""
        return self.scan_collection.get_status(scan_id)

    def scan_exists(self, scan_id):
        """ Checks if a scan with ID scan_id is in collection.

        @return: 1 if scan exists, 0 otherwise.
        """
        return self.scan_collection.id_exists(scan_id)

    def handle_get_scans_command(self, scan_et):
        """ Handles <get_scans> command.

        @return: Response string for <get_scans> command.
        """

        scan_id = scan_et.attrib.get('scan_id')
        details = scan_et.attrib.get('details')
        pop_res = scan_et.attrib.get('pop_results')
        if details and details == '0':
            details = False
        else:
            details = True
            if pop_res and pop_res == '1':
                pop_res = True
            else:
                pop_res = False

        responses = []
        if scan_id and scan_id in self.scan_collection.ids_iterator():
            self.check_scan_process(scan_id)
            scan = self.get_scan_xml(scan_id, details, pop_res)
            responses.append(scan)
        elif scan_id:
            text = "Failed to find scan '{0}'".format(scan_id)
            return simple_response_str('get_scans', 404, text)
        else:
            for scan_id in self.scan_collection.ids_iterator():
                self.check_scan_process(scan_id)
                scan = self.get_scan_xml(scan_id, details, pop_res)
                responses.append(scan)
        return simple_response_str('get_scans', 200, 'OK', responses)

    def handle_get_vts_command(self, vt_et):
        """ Handles <get_vts> command.

        @return: Response string for <get_vts> command.
        """

        vt_id = vt_et.attrib.get('vt_id')
        vt_filter = vt_et.attrib.get('filter')

        if vt_id and vt_id not in self.vts:
            text = "Failed to find vulnerability test '{0}'".format(vt_id)
            return simple_response_str('get_vts', 404, text)

        filtered_vts = None
        if vt_filter:
            filtered_vts = self.vts_filter.get_filtered_vts_list(
                self.vts, vt_filter
            )

        responses = []

        vts_xml = self.get_vts_xml(vt_id, filtered_vts)

        responses.append(vts_xml)

        return simple_response_str('get_vts', 200, 'OK', responses)

    def handle_get_performance(self, scan_et):
        """ Handles <get_performance> command.

        @return: Response string for <get_performance> command.
        """
        start = scan_et.attrib.get('start')
        end = scan_et.attrib.get('end')
        titles = scan_et.attrib.get('titles')

        cmd = ['gvmcg']
        if start:
            try:
                int(start)
            except ValueError:
                raise OspdCommandError(
                    'Start argument must be integer.',
                    'get_performance'
            )
            cmd.append(start)

        if end:
            try:
                int(end)
            except ValueError:
                raise OspdCommandError(
                    'End argument must be integer.',
                    'get_performance'
                )
            cmd.append(end)

        if titles:
            combined = "(" + ")|(".join(GVMCG_TITLES) + ")"
            forbidden = "^[^|&;]+$"
            if re.match(combined, titles) and re.match(forbidden, titles):
                cmd.append(titles)
            else:
                raise OspdCommandError(
                    'Arguments not allowed',
                    'get_performance'
                )

        try:
            output = subprocess.check_output(cmd)
        except (
                subprocess.CalledProcessError,
                PermissionError,
                FileNotFoundError,
        ) as e:
            raise OspdCommandError(
                'Bogus get_performance format. %s' % e,
                'get_performance'
            )

        return simple_response_str('get_performance', 200, 'OK', output.decode())

    def handle_help_command(self, scan_et):
        """ Handles <help> command.

        @return: Response string for <help> command.
        """
        help_format = scan_et.attrib.get('format')
        if help_format is None or help_format == "text":
            # Default help format is text.
            return simple_response_str('help', 200, 'OK', self.get_help_text())
        elif help_format == "xml":
            text = self.get_xml_str(self.commands)
            return simple_response_str('help', 200, 'OK', text)
        raise OspdCommandError('Bogus help format', 'help')

    def get_help_text(self):
        """ Returns the help output in plain text format."""

        txt = str('\n')
        for name, info in self.commands.items():
            command_txt = "\t{0: <22} {1}\n".format(name, info['description'])
            if info['attributes']:
                command_txt = ''.join([command_txt, "\t Attributes:\n"])
                for attrname, attrdesc in info['attributes'].items():
                    attr_txt = "\t  {0: <22} {1}\n".format(attrname, attrdesc)
                    command_txt = ''.join([command_txt, attr_txt])
            if info['elements']:
                command_txt = ''.join(
                    [
                        command_txt,
                        "\t Elements:\n",
                        self.elements_as_text(info['elements']),
                    ]
                )
            txt = ''.join([txt, command_txt])
        return txt

    def elements_as_text(self, elems, indent=2):
        """ Returns the elems dictionary as formatted plain text. """
        assert elems
        text = ""
        for elename, eledesc in elems.items():
            if isinstance(eledesc, dict):
                desc_txt = self.elements_as_text(eledesc, indent + 2)
                desc_txt = ''.join(['\n', desc_txt])
            elif isinstance(eledesc, str):
                desc_txt = ''.join([eledesc, '\n'])
            else:
                assert False, "Only string or dictionary"
            ele_txt = "\t{0}{1: <22} {2}".format(
                ' ' * indent, elename, desc_txt
            )
            text = ''.join([text, ele_txt])
        return text

    def handle_delete_scan_command(self, scan_et):
        """ Handles <delete_scan> command.

        @return: Response string for <delete_scan> command.
        """
        scan_id = scan_et.attrib.get('scan_id')
        if scan_id is None:
            return simple_response_str(
                'delete_scan', 404, 'No scan_id attribute'
            )

        if not self.scan_exists(scan_id):
            text = "Failed to find scan '{0}'".format(scan_id)
            return simple_response_str('delete_scan', 404, text)
        self.check_scan_process(scan_id)
        if self.delete_scan(scan_id):
            return simple_response_str('delete_scan', 200, 'OK')
        raise OspdCommandError('Scan in progress', 'delete_scan')

    def delete_scan(self, scan_id):
        """ Deletes scan_id scan from collection.

        @return: 1 if scan deleted, 0 otherwise.
        """
        if self.get_scan_status(scan_id) == ScanStatus.RUNNING:
            return 0

        try:
            del self.scan_processes[scan_id]
        except KeyError:
            logger.debug('Scan process for %s not found', scan_id)
        return self.scan_collection.delete_scan(scan_id)

    def get_scan_results_xml(self, scan_id, pop_res):
        """ Gets scan_id scan's results in XML format.

        @return: String of scan results in xml.
        """
        results = Element('results')
        for result in self.scan_collection.results_iterator(scan_id, pop_res):
            results.append(get_result_xml(result))

        logger.info('Returning %d results', len(results))
        return results

    def get_xml_str(self, data):
        """ Creates a string in XML Format using the provided data structure.

        @param: Dictionary of xml tags and their elements.

        @return: String of data in xml format.
        """

        responses = []
        for tag, value in data.items():
            elem = Element(tag)
            if isinstance(value, dict):
                for val in self.get_xml_str(value):
                    elem.append(val)
            elif isinstance(value, list):
                elem.text = ', '.join(value)
            else:
                elem.text = value
            responses.append(elem)
        return responses

    def get_scan_xml(self, scan_id, detailed=True, pop_res=False):
        """ Gets scan in XML format.

        @return: String of scan in XML format.
        """
        if not scan_id:
            return Element('scan')

        target = ','.join(self.get_scan_target(scan_id))
        progress = self.get_scan_progress(scan_id)
        status = self.get_scan_status(scan_id)
        start_time = self.get_scan_start_time(scan_id)
        end_time = self.get_scan_end_time(scan_id)
        response = Element('scan')
        for name, value in [
            ('id', scan_id),
            ('target', target),
            ('progress', progress),
            ('status', status.name.lower()),
            ('start_time', start_time),
            ('end_time', end_time),
        ]:
            response.set(name, str(value))
        if detailed:
            response.append(self.get_scan_results_xml(scan_id, pop_res))
        return response

    @staticmethod
    def get_custom_vt_as_xml_str(
        vt_id, custom
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        custom data object.
        This needs to be implemented by each ospd wrapper, in case
        custom elements for VTs are used.

        The custom XML object which is returned will be embedded
        into a <custom></custom> element.

        @return: XML object as string for custom data.
        """
        return ''

    @staticmethod
    def get_params_vt_as_xml_str(
        vt_id, vt_params
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        vt_params data object.
        This needs to be implemented by each ospd wrapper, in case
        vt_params elements for VTs are used.

        The params XML object which is returned will be embedded
        into a <params></params> element.

        @return: XML object as string for vt parameters data.
        """
        return ''

    @staticmethod
    def get_refs_vt_as_xml_str(
        vt_id, vt_refs
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        refs data object.
        This needs to be implemented by each ospd wrapper, in case
        refs elements for VTs are used.

        The refs XML object which is returned will be embedded
        into a <refs></refs> element.

        @return: XML object as string for vt references data.
        """
        return ''

    @staticmethod
    def get_dependencies_vt_as_xml_str(
        vt_id, vt_dependencies
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        vt_dependencies data object.
        This needs to be implemented by each ospd wrapper, in case
        vt_dependencies elements for VTs are used.

        The vt_dependencies XML object which is returned will be embedded
        into a <dependencies></dependencies> element.

        @return: XML object as string for vt dependencies data.
        """
        return ''

    @staticmethod
    def get_creation_time_vt_as_xml_str(
        vt_id, vt_creation_time
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        vt_creation_time data object.
        This needs to be implemented by each ospd wrapper, in case
        vt_creation_time elements for VTs are used.

        The vt_creation_time XML object which is returned will be embedded
        into a <vt_creation_time></vt_creation_time> element.

        @return: XML object as string for vt creation time data.
        """
        return ''

    @staticmethod
    def get_modification_time_vt_as_xml_str(
        vt_id, vt_modification_time
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        vt_modification_time data object.
        This needs to be implemented by each ospd wrapper, in case
        vt_modification_time elements for VTs are used.

        The vt_modification_time XML object which is returned will be embedded
        into a <vt_modification_time></vt_modification_time> element.

        @return: XML object as string for vt references data.
        """
        return ''

    @staticmethod
    def get_summary_vt_as_xml_str(
        vt_id, summary
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        summary data object.
        This needs to be implemented by each ospd wrapper, in case
        summary elements for VTs are used.

        The summary XML object which is returned will be embedded
        into a <summary></summary> element.

        @return: XML object as string for summary data.
        """
        return ''

    @staticmethod
    def get_impact_vt_as_xml_str(
        vt_id, impact
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        impact data object.
        This needs to be implemented by each ospd wrapper, in case
        impact elements for VTs are used.

        The impact XML object which is returned will be embedded
        into a <impact></impact> element.

        @return: XML object as string for impact data.
        """
        return ''

    @staticmethod
    def get_affected_vt_as_xml_str(
        vt_id, affected
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        affected data object.
        This needs to be implemented by each ospd wrapper, in case
        affected elements for VTs are used.

        The affected XML object which is returned will be embedded
        into a <affected></affected> element.

        @return: XML object as string for affected data.
        """
        return ''

    @staticmethod
    def get_insight_vt_as_xml_str(
        vt_id, insight
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        insight data object.
        This needs to be implemented by each ospd wrapper, in case
        insight elements for VTs are used.

        The insight XML object which is returned will be embedded
        into a <insight></insight> element.

        @return: XML object as string for insight data.
        """
        return ''

    @staticmethod
    def get_solution_vt_as_xml_str(
        vt_id, solution, solution_type=None
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        solution data object.
        This needs to be implemented by each ospd wrapper, in case
        solution elements for VTs are used.

        The solution XML object which is returned will be embedded
        into a <solution></solution> element.

        @return: XML object as string for solution data.
        """
        return ''

    @staticmethod
    def get_detection_vt_as_xml_str(
        vt_id, detection=None, qod_type=None, qod=None
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        detection data object.
        This needs to be implemented by each ospd wrapper, in case
        detection elements for VTs are used.

        The detection XML object which is returned is an element with
        tag <detection></detection> element

        @return: XML object as string for detection data.
        """
        return ''

    @staticmethod
    def get_severities_vt_as_xml_str(
        vt_id, severities
    ):  # pylint: disable=unused-argument
        """ Create a string representation of the XML object from the
        severities data object.
        This needs to be implemented by each ospd wrapper, in case
        severities elements for VTs are used.

        The severities XML objects which are returned will be embedded
        into a <severities></severities> element.

        @return: XML object as string for severities data.
        """
        return ''

    def get_vt_xml(self, vt_id):
        """ Gets a single vulnerability test information in XML format.

        @return: String of single vulnerability test information in XML format.
        """
        if not vt_id:
            return Element('vt')

        vt = self.vts.get(vt_id)

        name = vt.get('name')
        vt_xml = Element('vt')
        vt_xml.set('id', vt_id)

        for name, value in [('name', name)]:
            elem = SubElement(vt_xml, name)
            elem.text = str(value)

        if vt.get('vt_params'):
            params_xml_str = self.get_params_vt_as_xml_str(
                vt_id, vt.get('vt_params')
            )
            vt_xml.append(secET.fromstring(params_xml_str))

        if vt.get('vt_refs'):
            refs_xml_str = self.get_refs_vt_as_xml_str(vt_id, vt.get('vt_refs'))
            vt_xml.append(secET.fromstring(refs_xml_str))

        if vt.get('vt_dependencies'):
            dependencies = self.get_dependencies_vt_as_xml_str(
                vt_id, vt.get('vt_dependencies')
            )
            vt_xml.append(secET.fromstring(dependencies))

        if vt.get('creation_time'):
            vt_ctime = self.get_creation_time_vt_as_xml_str(
                vt_id, vt.get('creation_time')
            )
            vt_xml.append(secET.fromstring(vt_ctime))

        if vt.get('modification_time'):
            vt_mtime = self.get_modification_time_vt_as_xml_str(
                vt_id, vt.get('modification_time')
            )
            vt_xml.append(secET.fromstring(vt_mtime))

        if vt.get('summary'):
            summary_xml_str = self.get_summary_vt_as_xml_str(
                vt_id, vt.get('summary')
            )
            vt_xml.append(secET.fromstring(summary_xml_str))

        if vt.get('impact'):
            impact_xml_str = self.get_impact_vt_as_xml_str(
                vt_id, vt.get('impact')
            )
            vt_xml.append(secET.fromstring(impact_xml_str))

        if vt.get('affected'):
            affected_xml_str = self.get_affected_vt_as_xml_str(
                vt_id, vt.get('affected')
            )
            vt_xml.append(secET.fromstring(affected_xml_str))

        if vt.get('insight'):
            insight_xml_str = self.get_insight_vt_as_xml_str(
                vt_id, vt.get('insight')
            )
            vt_xml.append(secET.fromstring(insight_xml_str))

        if vt.get('solution'):
            solution_xml_str = self.get_solution_vt_as_xml_str(
                vt_id, vt.get('solution'), vt.get('solution_type')
            )
            vt_xml.append(secET.fromstring(solution_xml_str))

        if vt.get('detection') or vt.get('qod_type') or vt.get('qod'):
            detection_xml_str = self.get_detection_vt_as_xml_str(
                vt_id, vt.get('detection'), vt.get('qod_type'), vt.get('qod')
            )
            vt_xml.append(secET.fromstring(detection_xml_str))

        if vt.get('severities'):
            severities_xml_str = self.get_severities_vt_as_xml_str(
                vt_id, vt.get('severities')
            )
            vt_xml.append(secET.fromstring(severities_xml_str))

        if vt.get('custom'):
            custom_xml_str = self.get_custom_vt_as_xml_str(
                vt_id, vt.get('custom')
            )
            vt_xml.append(secET.fromstring(custom_xml_str))

        return vt_xml

    def get_vts_xml(self, vt_id=None, filtered_vts=None):
        """ Gets collection of vulnerability test information in XML format.
        If vt_id is specified, the collection will contain only this vt, if
        found.
        If no vt_id is specified, the collection will contain all vts or those
        passed in filtered_vts.

        Arguments:
            vt_id (vt_id, optional): ID of the vt to get.
            filtered_vts (dict, optional): Filtered VTs collection.

        Return:
            String of collection of vulnerability test information in
            XML format.
        """

        vts_xml = Element('vts')

        if vt_id:
            vts_xml.append(self.get_vt_xml(vt_id))
        elif filtered_vts:
            for vt_id in filtered_vts:
                vts_xml.append(self.get_vt_xml(vt_id))
        else:
            for vt_id in self.vts:
                vts_xml.append(self.get_vt_xml(vt_id))

        return vts_xml

    def handle_get_scanner_details(self):
        """ Handles <get_scanner_details> command.

        @return: Response string for <get_scanner_details> command.
        """
        desc_xml = Element('description')
        desc_xml.text = self.get_scanner_description()
        details = [desc_xml, self.get_scanner_params_xml()]
        return simple_response_str('get_scanner_details', 200, 'OK', details)

    def handle_get_version_command(self):
        """ Handles <get_version> command.

        @return: Response string for <get_version> command.
        """
        protocol = Element('protocol')
        for name, value in [
            ('name', 'OSP'),
            ('version', self.get_protocol_version()),
        ]:
            elem = SubElement(protocol, name)
            elem.text = value

        daemon = Element('daemon')
        for name, value in [
            ('name', self.get_daemon_name()),
            ('version', self.get_daemon_version()),
        ]:
            elem = SubElement(daemon, name)
            elem.text = value

        scanner = Element('scanner')
        for name, value in [
            ('name', self.get_scanner_name()),
            ('version', self.get_scanner_version()),
        ]:
            elem = SubElement(scanner, name)
            elem.text = value

        content = [protocol, daemon, scanner]

        if self.get_vts_version():
            vts = Element('vts')
            elem = SubElement(vts, 'version')
            elem.text = self.get_vts_version()
            content.append(vts)

        return simple_response_str('get_version', 200, 'OK', content)

    def handle_command(self, command):
        """ Handles an osp command in a string.

        @return: OSP Response to command.
        """
        try:
            tree = secET.fromstring(command)
        except secET.ParseError:
            logger.debug("Erroneous client input: %s", command)
            raise OspdCommandError('Invalid data')

        if not self.command_exists(tree.tag) and tree.tag != "authenticate":
            raise OspdCommandError('Bogus command name')

        if tree.tag == "get_version":
            return self.handle_get_version_command()
        elif tree.tag == "start_scan":
            return self.handle_start_scan_command(tree)
        elif tree.tag == "stop_scan":
            return self.handle_stop_scan_command(tree)
        elif tree.tag == "get_scans":
            return self.handle_get_scans_command(tree)
        elif tree.tag == "get_vts":
            return self.handle_get_vts_command(tree)
        elif tree.tag == "delete_scan":
            return self.handle_delete_scan_command(tree)
        elif tree.tag == "help":
            return self.handle_help_command(tree)
        elif tree.tag == "get_scanner_details":
            return self.handle_get_scanner_details()
        elif tree.tag == "get_performance":
            return self.handle_get_performance(tree)
        else:
            assert False, "Unhandled command: {0}".format(tree.tag)

    def check(self):
        """ Asserts to False. Should be implemented by subclass. """
        raise NotImplementedError

    def run(self, server: BaseServer):
        """ Starts the Daemon, handling commands until interrupted.
        """

        server.start(self.handle_client_stream)

        try:
            while True:
                time.sleep(10)
                self.scheduler()
        except KeyboardInterrupt:
            logger.info("Received Ctrl-C shutting-down ...")
        finally:
            logger.info("Shutting-down server ...")
            server.close()

    def scheduler(self):
        """ Should be implemented by subclass in case of need
        to run tasks periodically. """

    def create_scan(self, scan_id, targets, options, vts):
        """ Creates a new scan.

        @target: Target to scan.
        @options: Miscellaneous scan options.

        @return: New scan's ID.
        """
        if self.scan_exists(scan_id):
            logger.info("Scan %s exists. Resuming scan.", scan_id)

        return self.scan_collection.create_scan(scan_id, targets, options, vts)

    def get_scan_options(self, scan_id):
        """ Gives a scan's list of options. """
        return self.scan_collection.get_options(scan_id)

    def set_scan_option(self, scan_id, name, value):
        """ Sets a scan's option to a provided value. """
        return self.scan_collection.set_option(scan_id, name, value)

    def check_scan_process(self, scan_id):
        """ Check the scan's process, and terminate the scan if not alive. """
        scan_process = self.scan_processes[scan_id]
        progress = self.get_scan_progress(scan_id)
        if progress < 100 and not scan_process.is_alive():
            if not (self.get_scan_status(scan_id) == ScanStatus.STOPPED):
                self.set_scan_status(scan_id, ScanStatus.STOPPED)
                self.add_scan_error(
                    scan_id, name="", host="", value="Scan process failure."
                )
                logger.info("%s: Scan stopped with errors.", scan_id)
        elif progress == 100:
            scan_process.join()

    def get_scan_progress(self, scan_id):
        """ Gives a scan's current progress value. """
        return self.scan_collection.get_progress(scan_id)

    def get_scan_target_progress(self, scan_id, target):
        """ Gives a list with scan's current progress value of each target. """
        return self.scan_collection.get_target_progress(scan_id, target)

    def get_scan_target(self, scan_id):
        """ Gives a scan's target. """
        return self.scan_collection.get_target_list(scan_id)

    def get_scan_ports(self, scan_id, target=''):
        """ Gives a scan's ports list. """
        return self.scan_collection.get_ports(scan_id, target)

    def get_scan_exclude_hosts(self, scan_id, target=''):
        """ Gives a scan's exclude host list. If a target is passed gives
        the exclude host list for the given target. """
        return self.scan_collection.get_exclude_hosts(scan_id, target)

    def get_scan_credentials(self, scan_id, target=''):
        """ Gives a scan's credential list. If a target is passed gives
        the credential list for the given target. """
        return self.scan_collection.get_credentials(scan_id, target)

    def get_scan_vts(self, scan_id):
        """ Gives a scan's vts list. """
        return self.scan_collection.get_vts(scan_id)

    def get_scan_unfinished_hosts(self, scan_id):
        """ Get a list of unfinished hosts."""
        return self.scan_collection.get_hosts_unfinished(scan_id)

    def get_scan_finished_hosts(self, scan_id):
        """ Get a list of unfinished hosts."""
        return self.scan_collection.get_hosts_finished(scan_id)

    def get_scan_start_time(self, scan_id):
        """ Gives a scan's start time. """
        return self.scan_collection.get_start_time(scan_id)

    def get_scan_end_time(self, scan_id):
        """ Gives a scan's end time. """
        return self.scan_collection.get_end_time(scan_id)

    def add_scan_log(
        self,
        scan_id,
        host='',
        hostname='',
        name='',
        value='',
        port='',
        test_id='',
        qod='',
    ):
        """ Adds a log result to scan_id scan. """
        self.scan_collection.add_result(
            scan_id,
            ResultType.LOG,
            host,
            hostname,
            name,
            value,
            port,
            test_id,
            0.0,
            qod,
        )

    def add_scan_error(
        self, scan_id, host='', hostname='', name='', value='', port=''
    ):
        """ Adds an error result to scan_id scan. """
        self.scan_collection.add_result(
            scan_id, ResultType.ERROR, host, hostname, name, value, port
        )

    def add_scan_host_detail(
        self, scan_id, host='', hostname='', name='', value=''
    ):
        """ Adds a host detail result to scan_id scan. """
        self.scan_collection.add_result(
            scan_id, ResultType.HOST_DETAIL, host, hostname, name, value
        )

    def add_scan_alarm(
        self,
        scan_id,
        host='',
        hostname='',
        name='',
        value='',
        port='',
        test_id='',
        severity='',
        qod='',
    ):
        """ Adds an alarm result to scan_id scan. """
        self.scan_collection.add_result(
            scan_id,
            ResultType.ALARM,
            host,
            hostname,
            name,
            value,
            port,
            test_id,
            severity,
            qod,
        )
