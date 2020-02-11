# Copyright (C) 2014-2020 Greenbone Networks GmbH
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

import logging
import socket
import ssl
import multiprocessing
import time
import os

from typing import List, Any, Dict, Optional
from xml.etree.ElementTree import Element, SubElement

import defusedxml.ElementTree as secET

from deprecated import deprecated

from ospd import __version__
from ospd.command import get_commands
from ospd.errors import OspdCommandError
from ospd.misc import ScanCollection, ResultType, ScanStatus, create_process
from ospd.network import resolve_hostname, target_str_to_list
from ospd.protocol import OspRequest, OspResponse
from ospd.server import BaseServer
from ospd.vtfilter import VtsFilter
from ospd.vts import Vts
from ospd.xml import (
    elements_as_text,
    get_result_xml,
    get_elements_from_dict,
)

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "1.2"

SCHEDULER_CHECK_PERIOD = 5  # in seconds

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
}  # type: Dict


def _terminate_process_group(process: multiprocessing.Process) -> None:
    os.killpg(os.getpgid(process.pid), 15)


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

        self.scaninfo_store_time = kwargs.get('scaninfo_store_time')

        self.protocol_version = PROTOCOL_VERSION

        self.commands = {}

        for command_class in get_commands():
            command = command_class(self)
            self.commands[command.get_name()] = command

        self.scanner_params = dict()

        for name, params in BASE_SCANNER_PARAMS.items():
            self.set_scanner_param(name, params)

        self.vts = Vts()
        self.vts_version = None

        if customvtfilter:
            self.vts_filter = customvtfilter
        else:
            self.vts_filter = VtsFilter()

    def init(self) -> None:
        """ Should be overridden by a subclass if the initialization is costly.

            Will be called after check.
        """

    def set_command_attributes(self, name: str, attributes: Dict) -> None:
        """ Sets the xml attributes of a specified command. """
        if self.command_exists(name):
            command = self.commands.get(name)
            command.attributes = attributes

    @deprecated(version="20.4", reason="Use set_scanner_param instead")
    def add_scanner_param(self, name: str, scanner_params: Dict) -> None:
        """ Set a scanner parameter. """
        self.set_scanner_param(name, scanner_params)

    def set_scanner_param(self, name: str, scanner_params: Dict) -> None:
        """ Set a scanner parameter. """

        assert name
        assert scanner_params

        self.scanner_params[name] = scanner_params

    def get_scanner_params(self) -> Dict:
        return self.scanner_params

    def add_vt(
        self,
        vt_id: str,
        name: str = None,
        vt_params: str = None,
        vt_refs: str = None,
        custom: str = None,
        vt_creation_time: str = None,
        vt_modification_time: str = None,
        vt_dependencies: str = None,
        summary: str = None,
        impact: str = None,
        affected: str = None,
        insight: str = None,
        solution: str = None,
        solution_t: str = None,
        solution_m: str = None,
        detection: str = None,
        qod_t: str = None,
        qod_v: str = None,
        severities: str = None,
    ) -> None:
        """ Add a vulnerability test information.

        IMPORTANT: The VT's Data Manager will store the vts collection.
        If the collection is considerably big and it will be consultated
        intensible during a routine, consider to do a deepcopy(), since
        accessing the shared memory in the data manager is very expensive.
        At the end of the routine, the temporal copy must be set to None
        and deleted.
        """
        self.vts.add(
            vt_id,
            name=name,
            vt_params=vt_params,
            vt_refs=vt_refs,
            custom=custom,
            vt_creation_time=vt_creation_time,
            vt_modification_time=vt_modification_time,
            vt_dependencies=vt_dependencies,
            summary=summary,
            impact=impact,
            affected=affected,
            insight=insight,
            solution=solution,
            solution_t=solution_t,
            solution_m=solution_m,
            detection=detection,
            qod_t=qod_t,
            qod_v=qod_v,
            severities=severities,
        )

    def set_vts_version(self, vts_version: str) -> None:
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

    def get_vts_version(self) -> Optional[str]:
        """Return the vts version.
        """
        return self.vts_version

    def command_exists(self, name: str) -> bool:
        """ Checks if a commands exists. """
        return name in self.commands

    def get_scanner_name(self) -> str:
        """ Gives the wrapped scanner's name. """
        return self.scanner_info['name']

    def get_scanner_version(self) -> str:
        """ Gives the wrapped scanner's version. """
        return self.scanner_info['version']

    def get_scanner_description(self) -> str:
        """ Gives the wrapped scanner's description. """
        return self.scanner_info['description']

    def get_server_version(self) -> str:
        """ Gives the specific OSP server's version. """
        assert self.server_version
        return self.server_version

    def get_protocol_version(self) -> str:
        """ Gives the OSP's version. """
        return self.protocol_version

    def preprocess_scan_params(self, xml_params):
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

    def process_scan_params(self, params: Dict) -> Dict:
        """ This method is to be overridden by the child classes if necessary
        """
        return params

    @staticmethod
    @deprecated(
        version="20.4",
        reason="Please use OspRequest.process_vt_params instead.",
    )
    def process_vts_params(scanner_vts) -> Dict:
        return OspRequest.process_vts_params(scanner_vts)

    @staticmethod
    @deprecated(
        version="20.4",
        reason="Please use OspRequest.process_credential_elements instead.",
    )
    def process_credentials_elements(cred_tree) -> Dict:
        return OspRequest.process_credentials_elements(cred_tree)

    @staticmethod
    @deprecated(
        version="20.4",
        reason="Please use OspRequest.process_targets_elements instead.",
    )
    def process_targets_element(scanner_target) -> List:
        return OspRequest.process_targets_element(scanner_target)

    def stop_scan(self, scan_id: str) -> None:
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

        try:
            _terminate_process_group(scan_process)
        except ProcessLookupError as e:
            logger.info(
                '%s: Scan already stopped %s.', scan_id, scan_process.pid
            )

        if scan_process.ident != os.getpid():
            scan_process.join(0)

        logger.info('%s: Scan stopped.', scan_id)

    @staticmethod
    def stop_scan_cleanup(scan_id: str):
        """ Should be implemented by subclass in case of a clean up before
        terminating is needed. """

    @staticmethod
    def target_is_finished(scan_id: str):
        """ Should be implemented by subclass in case of a check before
        stopping is needed. """

    def exec_scan(self, scan_id: str, target):
        """ Asserts to False. Should be implemented by subclass. """
        raise NotImplementedError

    def finish_scan(self, scan_id: str) -> None:
        """ Sets a scan as finished. """
        self.set_scan_progress(scan_id, 100)
        self.set_scan_status(scan_id, ScanStatus.FINISHED)
        logger.info("%s: Scan finished.", scan_id)

    def get_daemon_name(self) -> str:
        """ Gives osp daemon's name. """
        return self.daemon_info['name']

    def get_daemon_version(self) -> str:
        """ Gives osp daemon's version. """
        return self.daemon_info['version']

    def get_scanner_param_type(self, param: str):
        """ Returns type of a scanner parameter. """
        assert isinstance(param, str)
        entry = self.scanner_params.get(param)
        if not entry:
            return None
        return entry.get('type')

    def get_scanner_param_mandatory(self, param: str):
        """ Returns if a scanner parameter is mandatory. """
        assert isinstance(param, str)
        entry = self.scanner_params.get(param)
        if not entry:
            return False
        return entry.get('mandatory')

    def get_scanner_param_default(self, param: str):
        """ Returns default value of a scanner parameter. """
        assert isinstance(param, str)
        entry = self.scanner_params.get(param)
        if not entry:
            return None
        return entry.get('default')

    @deprecated(
        version="20.4",
        reason="Please use OspResponse.create_scanner_params_xml instead.",
    )
    def get_scanner_params_xml(self):
        """ Returns the OSP Daemon's scanner params in xml format. """
        return OspResponse.create_scanner_params_xml(self.scanner_params)

    def handle_client_stream(self, stream) -> None:
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

        response = None
        try:
            self.handle_command(data, stream)
        except OspdCommandError as exception:
            response = exception.as_xml()
            logger.debug('Command error: %s', exception.message)
        except Exception:  # pylint: disable=broad-except
            logger.exception('While handling client command:')
            exception = OspdCommandError('Fatal error', 'error')
            response = exception.as_xml()

        if response:
            stream.write(response)
        stream.close()

    def parallel_scan(self, scan_id: str, target: str) -> None:
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

    def check_pending_target(self, scan_id: str, multiscan_proc: List) -> List:
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

    def calculate_progress(self, scan_id: str) -> float:
        """ Calculate the total scan progress from the
        partial target progress. """

        t_prog = dict()
        for target in self.get_scan_target(scan_id):
            t_prog[target] = self.get_scan_target_progress(scan_id, target)
        return sum(t_prog.values()) / len(t_prog)

    def process_exclude_hosts(self, scan_id: str, target_list: List) -> None:
        """ Process the exclude hosts before launching the scans."""

        for target, _, _, exclude_hosts, _, _ in target_list:
            exc_hosts_list = ''
            if not exclude_hosts:
                continue
            exc_hosts_list = target_str_to_list(exclude_hosts)
            self.remove_scan_hosts_from_target_progress(
                scan_id, target, exc_hosts_list
            )

    def process_finished_hosts(self, scan_id: str, target_list: List) -> None:
        """ Process the finished hosts before launching the scans.
        Set finished hosts as finished with 100% to calculate
        the scan progress."""

        for target, _, _, _, finished_hosts, _ in target_list:
            exc_hosts_list = ''
            if not finished_hosts:
                continue
            exc_hosts_list = target_str_to_list(finished_hosts)

            for host in exc_hosts_list:
                self.set_scan_host_finished(scan_id, target, host)
                self.set_scan_host_progress(scan_id, target, host, 100)

    def start_scan(self, scan_id: str, targets: List, parallel=1) -> None:
        """ Handle N parallel scans if 'parallel' is greater than 1. """

        os.setsid()

        multiscan_proc = []
        logger.info("%s: Scan started.", scan_id)
        target_list = targets
        if target_list is None or not target_list:
            raise OspdCommandError('Erroneous targets list', 'start_scan')

        self.process_exclude_hosts(scan_id, target_list)
        self.process_finished_hosts(scan_id, target_list)

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

            logger.debug(
                "%s: Host scan started on ports %s.", target[0], target[1]
            )
            scan_process = create_process(
                func=self.parallel_scan, args=(scan_id, target[0])
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

    def dry_run_scan(  # pylint: disable=unused-argument
        self, scan_id: str, targets: List, parallel: int
    ) -> None:
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

    def handle_timeout(self, scan_id: str, host: str) -> None:
        """ Handles scanner reaching timeout error. """
        self.add_scan_error(
            scan_id,
            host=host,
            name="Timeout",
            value="{0} exec timeout.".format(self.get_scanner_name()),
        )

    def remove_scan_hosts_from_target_progress(
        self, scan_id: str, target: str, exc_hosts_list: List
    ) -> None:
        """ Remove a list of hosts from the main scan progress table."""
        self.scan_collection.remove_hosts_from_target_progress(
            scan_id, target, exc_hosts_list
        )

    def set_scan_host_finished(
        self, scan_id: str, target: str, host: str
    ) -> None:
        """ Add the host in a list of finished hosts """
        self.scan_collection.set_host_finished(scan_id, target, host)

    def set_scan_progress(self, scan_id: str, progress: int) -> None:
        """ Sets scan_id scan's progress which is a number
        between 0 and 100. """
        self.scan_collection.set_progress(scan_id, progress)

    def set_scan_host_progress(
        self, scan_id: str, target: str, host: str, progress: int
    ) -> None:
        """ Sets host's progress which is part of target. """
        self.scan_collection.set_host_progress(scan_id, target, host, progress)

    def set_scan_status(self, scan_id: str, status: ScanStatus) -> None:
        """ Set the scan's status."""
        self.scan_collection.set_status(scan_id, status)

    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """ Get scan_id scans's status."""
        return self.scan_collection.get_status(scan_id)

    def scan_exists(self, scan_id: str) -> bool:
        """ Checks if a scan with ID scan_id is in collection.

        @return: 1 if scan exists, 0 otherwise.
        """
        return self.scan_collection.id_exists(scan_id)

    def get_help_text(self) -> str:
        """ Returns the help output in plain text format."""

        txt = ''
        for name, info in self.commands.items():
            description = info.get_description()
            attributes = info.get_attributes()
            elements = info.get_elements()

            command_txt = "\t{0: <22} {1}\n".format(name, description)

            if attributes:
                command_txt = ''.join([command_txt, "\t Attributes:\n"])

                for attrname, attrdesc in attributes.items():
                    attr_txt = "\t  {0: <22} {1}\n".format(attrname, attrdesc)
                    command_txt = ''.join([command_txt, attr_txt])

            if elements:
                command_txt = ''.join(
                    [command_txt, "\t Elements:\n", elements_as_text(elements),]
                )

            txt += command_txt

        return txt

    @deprecated(version="20.4", reason="Use ospd.xml.elements_as_text instead.")
    def elements_as_text(self, elems: Dict, indent: int = 2) -> str:
        """ Returns the elems dictionary as formatted plain text. """
        return elements_as_text(elems, indent)

    def delete_scan(self, scan_id: str) -> int:
        """ Deletes scan_id scan from collection.

        @return: 1 if scan deleted, 0 otherwise.
        """
        if self.get_scan_status(scan_id) == ScanStatus.RUNNING:
            return 0

        # Don't delete the scan until the process stops
        exitcode = None
        try:
            self.scan_processes[scan_id].join()
            exitcode = self.scan_processes[scan_id].exitcode
        except KeyError:
            logger.debug('Scan process for %s not found', scan_id)

        if exitcode or exitcode == 0:
            del self.scan_processes[scan_id]

        return self.scan_collection.delete_scan(scan_id)

    def get_scan_results_xml(
        self, scan_id: str, pop_res: bool, max_res: Optional[int]
    ):
        """ Gets scan_id scan's results in XML format.

        @return: String of scan results in xml.
        """
        results = Element('results')
        for result in self.scan_collection.results_iterator(
            scan_id, pop_res, max_res
        ):
            results.append(get_result_xml(result))

        logger.debug('Returning %d results', len(results))
        return results

    @deprecated(
        version="20.4",
        reason="Please use ospd.xml.get_elements_from_dict instead.",
    )
    def get_xml_str(self, data: Dict) -> List:
        """ Creates a string in XML Format using the provided data structure.

        @param: Dictionary of xml tags and their elements.

        @return: String of data in xml format.
        """
        return get_elements_from_dict(data)

    def get_scan_xml(
        self,
        scan_id: str,
        detailed: bool = True,
        pop_res: bool = False,
        max_res: int = 0,
    ):
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
            response.append(
                self.get_scan_results_xml(scan_id, pop_res, max_res)
            )
        return response

    @staticmethod
    def get_custom_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, custom: Dict
    ) -> str:
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
    def get_params_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_params
    ) -> str:
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
    def get_refs_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_refs
    ) -> str:
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
    def get_dependencies_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_dependencies
    ) -> str:
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
    def get_creation_time_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_creation_time
    ) -> str:
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
    def get_modification_time_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_modification_time
    ) -> str:
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
    def get_summary_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, summary
    ) -> str:
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
    def get_impact_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, impact
    ) -> str:
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
    def get_affected_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, affected
    ) -> str:
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
    def get_insight_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, insight
    ) -> str:
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
    def get_solution_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, solution, solution_type=None, solution_method=None
    ) -> str:
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
    def get_detection_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, detection=None, qod_type=None, qod=None
    ) -> str:
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
    def get_severities_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, severities
    ) -> str:
        """ Create a string representation of the XML object from the
        severities data object.
        This needs to be implemented by each ospd wrapper, in case
        severities elements for VTs are used.

        The severities XML objects which are returned will be embedded
        into a <severities></severities> element.

        @return: XML object as string for severities data.
        """
        return ''

    def get_vt_xml(self, vt_id: str):
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
                vt_id,
                vt.get('solution'),
                vt.get('solution_type'),
                vt.get('solution_method'),
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

    def get_vts_selection_list(
        self, vt_id: str = None, filtered_vts: Dict = None
    ) -> List:
        """
        Get list of VT's OID.
        If vt_id is specified, the collection will contain only this vt, if
        found.
        If no vt_id is specified or filtered_vts is None (default), the
        collection will contain all vts. Otherwise those vts passed
        in filtered_vts or vt_id are returned. In case of both vt_id and
        filtered_vts are given, filtered_vts has priority.

        Arguments:
            vt_id (vt_id, optional): ID of the vt to get.
            filtered_vts (list, optional): Filtered VTs collection.

        Return:
            List of selected VT's OID.
        """
        vts_xml = []
        if not self.vts:
            return vts_xml

        # No match for the filter
        if filtered_vts is not None and len(filtered_vts) == 0:
            return vts_xml

        if filtered_vts:
            vts_list = filtered_vts
        elif vt_id:
            vts_list = [vt_id]
        else:
            # TODO: Because DictProxy for python3.5 doesn't support
            # iterkeys(), itervalues(), or iteritems() either, the iteration
            # must be done as follow.
            vts_list = iter(self.vts.keys())

        return vts_list

    def handle_command(self, command: str, stream) -> str:
        """ Handles an osp command in a string.

        @return: OSP Response to command.
        """
        try:
            tree = secET.fromstring(command)
        except secET.ParseError:
            logger.debug("Erroneous client input: %s", command)
            raise OspdCommandError('Invalid data')

        command = self.commands.get(tree.tag, None)
        if not command and tree.tag != "authenticate":
            raise OspdCommandError('Bogus command name')

        response = command.handle_xml(tree)

        if isinstance(response, bytes):
            stream.write(response)
        else:
            for data in response:
                stream.write(data)

    def check(self):
        """ Asserts to False. Should be implemented by subclass. """
        raise NotImplementedError

    def run(self, server: BaseServer) -> None:
        """ Starts the Daemon, handling commands until interrupted.
        """

        server.start(self.handle_client_stream)

        try:
            while True:
                time.sleep(10)
                self.scheduler()
                self.clean_forgotten_scans()
                self.wait_for_children()
        except KeyboardInterrupt:
            logger.info("Received Ctrl-C shutting-down ...")
        finally:
            logger.info("Shutting-down server ...")
            server.close()

    def scheduler(self):
        """ Should be implemented by subclass in case of need
        to run tasks periodically. """

    def wait_for_children(self):
        """ Join the zombie process to releases resources."""
        for scan_id in self.scan_processes:
            self.scan_processes[scan_id].join(0)

    def create_scan(
        self,
        scan_id: str,
        targets: List,
        options: Optional[Dict],
        vt_selection: Dict,
    ) -> Optional[str]:
        """ Creates a new scan.

        @target: Target to scan.
        @options: Miscellaneous scan options.

        @return: New scan's ID. None if the scan_id already exists and the
                 scan status is RUNNING or FINISHED.
        """
        status = None
        scan_exists = self.scan_exists(scan_id)
        if scan_id and scan_exists:
            status = self.get_scan_status(scan_id)

        if scan_exists and status == ScanStatus.STOPPED:
            logger.info("Scan %s exists. Resuming scan.", scan_id)
        elif scan_exists and (
            status == ScanStatus.RUNNING or status == ScanStatus.FINISHED
        ):
            logger.info(
                "Scan %s exists with status %s.", scan_id, status.name.lower()
            )
            return
        return self.scan_collection.create_scan(
            scan_id, targets, options, vt_selection
        )

    def get_scan_options(self, scan_id: str) -> str:
        """ Gives a scan's list of options. """
        return self.scan_collection.get_options(scan_id)

    def set_scan_option(self, scan_id: str, name: str, value: Any) -> None:
        """ Sets a scan's option to a provided value. """
        return self.scan_collection.set_option(scan_id, name, value)

    def clean_forgotten_scans(self) -> None:
        """ Check for old stopped or finished scans which have not been
        deleted and delete them if the are older than the set value."""

        if not self.scaninfo_store_time:
            return

        for scan_id in list(self.scan_collection.ids_iterator()):
            end_time = int(self.get_scan_end_time(scan_id))
            scan_status = self.get_scan_status(scan_id)

            if (
                scan_status == ScanStatus.STOPPED
                or scan_status == ScanStatus.FINISHED
            ) and end_time:
                stored_time = int(time.time()) - end_time
                if stored_time > self.scaninfo_store_time * 3600:
                    logger.debug(
                        'Scan %s is older than %d hours and seems have been '
                        'forgotten. Scan info will be deleted from the '
                        'scan table',
                        scan_id,
                        self.scaninfo_store_time,
                    )
                    self.delete_scan(scan_id)

    def check_scan_process(self, scan_id: str) -> None:
        """ Check the scan's process, and terminate the scan if not alive. """
        scan_process = self.scan_processes[scan_id]
        progress = self.get_scan_progress(scan_id)

        if progress < 100 and not scan_process.is_alive():
            if not self.get_scan_status(scan_id) == ScanStatus.STOPPED:
                self.set_scan_status(scan_id, ScanStatus.STOPPED)
                self.add_scan_error(
                    scan_id, name="", host="", value="Scan process failure."
                )

                logger.info("%s: Scan stopped with errors.", scan_id)

        elif progress == 100:
            scan_process.join(0)

    def get_scan_progress(self, scan_id: str):
        """ Gives a scan's current progress value. """
        return self.scan_collection.get_progress(scan_id)

    def get_scan_target_progress(self, scan_id: str, target: str) -> float:
        """ Gives a list with scan's current progress value of each target. """
        return self.scan_collection.get_target_progress(scan_id, target)

    def get_scan_target(self, scan_id: str) -> List:
        """ Gives a scan's target. """
        return self.scan_collection.get_target_list(scan_id)

    def get_scan_ports(self, scan_id: str, target: str = '') -> str:
        """ Gives a scan's ports list. """
        return self.scan_collection.get_ports(scan_id, target)

    def get_scan_exclude_hosts(self, scan_id: str, target: str = ''):
        """ Gives a scan's exclude host list. If a target is passed gives
        the exclude host list for the given target. """
        return self.scan_collection.get_exclude_hosts(scan_id, target)

    def get_scan_credentials(self, scan_id: str, target: str = '') -> Dict:
        """ Gives a scan's credential list. If a target is passed gives
        the credential list for the given target. """
        return self.scan_collection.get_credentials(scan_id, target)

    def get_scan_target_options(self, scan_id: str, target: str = '') -> Dict:
        """ Gives a scan's target option dict. If a target is passed gives
        the credential list for the given target. """
        return self.scan_collection.get_target_options(scan_id, target)

    def get_scan_vts(self, scan_id: str) -> Dict:
        """ Gives a scan's vts. """
        return self.scan_collection.get_vts(scan_id)

    def get_scan_unfinished_hosts(self, scan_id: str) -> List:
        """ Get a list of unfinished hosts."""
        return self.scan_collection.get_hosts_unfinished(scan_id)

    def get_scan_finished_hosts(self, scan_id: str) -> List:
        """ Get a list of unfinished hosts."""
        return self.scan_collection.get_hosts_finished(scan_id)

    def get_scan_start_time(self, scan_id: str) -> str:
        """ Gives a scan's start time. """
        return self.scan_collection.get_start_time(scan_id)

    def get_scan_end_time(self, scan_id: str) -> str:
        """ Gives a scan's end time. """
        return self.scan_collection.get_end_time(scan_id)

    def add_scan_log(
        self,
        scan_id: str,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        qod: str = '',
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
            '0.0',
            qod,
        )

    def add_scan_error(
        self,
        scan_id: str,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
    ) -> None:
        """ Adds an error result to scan_id scan. """
        self.scan_collection.add_result(
            scan_id, ResultType.ERROR, host, hostname, name, value, port
        )

    def add_scan_host_detail(
        self,
        scan_id: str,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
    ) -> None:
        """ Adds a host detail result to scan_id scan. """
        self.scan_collection.add_result(
            scan_id, ResultType.HOST_DETAIL, host, hostname, name, value
        )

    def add_scan_alarm(
        self,
        scan_id: str,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        severity: str = '',
        qod: str = '',
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
