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

# pylint: disable=too-many-lines

""" OSP Daemon core class.
"""

import logging
import socket
import ssl
import multiprocessing
import time
import os

from pprint import pformat
from typing import List, Any, Iterator, Dict, Optional, Iterable, Tuple, Union
from xml.etree.ElementTree import Element, SubElement

import defusedxml.ElementTree as secET

import psutil

from ospd import __version__
from ospd.command import get_commands
from ospd.errors import OspdCommandError
from ospd.misc import ResultType, create_process
from ospd.network import resolve_hostname, target_str_to_list
from ospd.protocol import RequestParser
from ospd.scan import ScanCollection, ScanStatus, ScanProgress
from ospd.server import BaseServer, Stream
from ospd.vtfilter import VtsFilter
from ospd.vts import Vts
from ospd.xml import elements_as_text, get_result_xml, get_progress_xml

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = __version__

SCHEDULER_CHECK_PERIOD = 10  # in seconds

MIN_TIME_BETWEEN_START_SCAN = 60  # in seconds

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

    """Daemon class for OSP traffic handling.

    Every scanner wrapper should subclass it and make necessary additions and
    changes.

    * Add any needed parameters in __init__.
    * Implement check() method which verifies scanner availability and other
      environment related conditions.
    * Implement process_scan_params and exec_scan methods which are
      specific to handling the <start_scan> command, executing the wrapped
      scanner and storing the results.
    * Implement other methods that assert to False such as get_scanner_name,
      get_scanner_version.
    * Use Call set_command_attributes at init time to add scanner command
      specific options eg. the w3af profile for w3af wrapper.
    """

    def __init__(
        self,
        *,
        customvtfilter=None,
        storage=None,
        max_scans=0,
        min_free_mem_scan_queue=0,
        file_storage_dir='/var/run/ospd',
        max_queued_scans=0,
        **kwargs,
    ):  # pylint: disable=unused-argument
        """ Initializes the daemon's internal data. """
        self.scan_collection = ScanCollection(file_storage_dir)
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

        self.initialized = None  # Set after initialization finished

        self.max_scans = max_scans
        self.min_free_mem_scan_queue = min_free_mem_scan_queue
        self.max_queued_scans = max_queued_scans
        self.last_scan_start_time = 0

        self.scaninfo_store_time = kwargs.get('scaninfo_store_time')

        self.protocol_version = PROTOCOL_VERSION

        self.commands = {}

        for command_class in get_commands():
            command = command_class(self)
            self.commands[command.get_name()] = command

        self.scanner_params = dict()

        for name, params in BASE_SCANNER_PARAMS.items():
            self.set_scanner_param(name, params)

        self.vts = Vts(storage)
        self.vts_version = None

        if customvtfilter:
            self.vts_filter = customvtfilter
        else:
            self.vts_filter = VtsFilter()

    def init(self, server: BaseServer) -> None:
        """Should be overridden by a subclass if the initialization is costly.

        Will be called after check.
        """
        self.scan_collection.init()
        server.start(self.handle_client_stream)
        self.initialized = True

    def set_command_attributes(self, name: str, attributes: Dict) -> None:
        """ Sets the xml attributes of a specified command. """
        if self.command_exists(name):
            command = self.commands.get(name)
            command.attributes = attributes

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
        """Add a vulnerability test information.

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
        """Add into the vts dictionary an entry to identify the
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
        """Return the vts version."""
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
                    ) from None

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
        """This method is to be overridden by the child classes if necessary"""
        return params

    def stop_scan(self, scan_id: str) -> None:
        if (
            scan_id in self.scan_collection.ids_iterator()
            and self.get_scan_status(scan_id) == ScanStatus.QUEUED
        ):
            logger.info('Scan %s has been removed from the queue.', scan_id)
            self.scan_collection.remove_file_pickled_scan_info(scan_id)
            self.set_scan_status(scan_id, ScanStatus.STOPPED)

            return

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

        logger.info(
            '%s: Stopping Scan with the PID %s.', scan_id, scan_process.ident
        )

        try:
            scan_process.terminate()
        except AttributeError:
            logger.debug('%s: The scanner task stopped unexpectedly.', scan_id)

        try:
            logger.debug(
                '%s: Terminating process group after stopping.', scan_id
            )
            _terminate_process_group(scan_process)
        except ProcessLookupError:
            logger.info(
                '%s: Scan with the PID %s is already stopped.',
                scan_id,
                scan_process.pid,
            )

        if scan_process.ident != os.getpid():
            scan_process.join(0)

        logger.info('%s: Scan stopped.', scan_id)

    def exec_scan(self, scan_id: str):
        """ Asserts to False. Should be implemented by subclass. """
        raise NotImplementedError

    def finish_scan(self, scan_id: str) -> None:
        """ Sets a scan as finished. """
        self.scan_collection.set_progress(scan_id, ScanProgress.FINISHED.value)
        self.set_scan_status(scan_id, ScanStatus.FINISHED)
        logger.info("%s: Scan finished.", scan_id)

    def interrupt_scan(self, scan_id: str) -> None:
        """ Set scan status as interrupted. """
        self.set_scan_status(scan_id, ScanStatus.INTERRUPTED)
        logger.info("%s: Scan interrupted.", scan_id)

    def daemon_exit_cleanup(self) -> None:
        """ Perform a cleanup before exiting """
        self.scan_collection.clean_up_pickled_scan_info()

        # Stop scans which are not already stopped.
        for scan_id in self.scan_collection.ids_iterator():
            status = self.get_scan_status(scan_id)
            if (
                status != ScanStatus.STOPPED
                and status != ScanStatus.FINISHED
                and status != ScanStatus.INTERRUPTED
            ):
                logger.debug("%s: Stopping scan before daemon exit.", scan_id)
                self.stop_scan(scan_id)

        # Wait for scans to be in some stopped state.
        while True:
            all_stopped = True
            for scan_id in self.scan_collection.ids_iterator():
                status = self.get_scan_status(scan_id)
                if (
                    status != ScanStatus.STOPPED
                    and status != ScanStatus.FINISHED
                    and status != ScanStatus.INTERRUPTED
                ):
                    all_stopped = False

            if all_stopped:
                logger.debug(
                    "All scans stopped and daemon clean and ready to exit"
                )
                return

            logger.debug("Waiting for running scans before daemon exit. ")
            time.sleep(1)

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

    def handle_client_stream(self, stream: Stream) -> None:
        """ Handles stream of data received from client. """
        data = b''

        request_parser = RequestParser()

        while True:
            try:
                buf = stream.read()
                if not buf:
                    break

                data += buf

                if request_parser.has_ended(buf):
                    break
            except (AttributeError, ValueError) as message:
                logger.error(message)
                return
            except (ssl.SSLError) as exception:
                logger.debug('Error: %s', exception)
                break
            except (socket.timeout) as exception:
                logger.debug('Request timeout: %s', exception)
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

    def process_finished_hosts(self, scan_id: str) -> None:
        """ Process the finished hosts before launching the scans."""

        finished_hosts = self.scan_collection.get_finished_hosts(scan_id)
        if not finished_hosts:
            return

        exc_finished_hosts_list = target_str_to_list(finished_hosts)
        self.scan_collection.set_host_finished(scan_id, exc_finished_hosts_list)

    def start_scan(self, scan_id: str) -> None:
        """ Starts the scan with scan_id. """
        os.setsid()

        self.process_finished_hosts(scan_id)

        try:
            self.set_scan_status(scan_id, ScanStatus.RUNNING)
            self.exec_scan(scan_id)
        except Exception as e:  # pylint: disable=broad-except
            self.add_scan_error(
                scan_id,
                name='',
                host=self.get_scan_host(scan_id),
                value='Host process failure (%s).' % e,
            )
            logger.exception('%s: Exception %s while scanning', scan_id, e)
        else:
            logger.info("%s: Host scan finished.", scan_id)

        status = self.get_scan_status(scan_id)
        is_stopped = status == ScanStatus.STOPPED
        self.set_scan_progress(scan_id)
        progress = self.get_scan_progress(scan_id)
        if not is_stopped and progress == ScanProgress.FINISHED:
            self.finish_scan(scan_id)
        elif not is_stopped:
            logger.info(
                "%s: Host scan got interrupted. Progress: %d, Status: %s",
                scan_id,
                progress,
                status.name,
            )
            self.interrupt_scan(scan_id)

        # For debug purposes
        self._get_scan_progress_raw(scan_id)

    def dry_run_scan(self, scan_id: str, target: Dict) -> None:
        """ Dry runs a scan. """

        os.setsid()

        host = resolve_hostname(target.get('hosts'))
        if host is None:
            logger.info("Couldn't resolve %s.", self.get_scan_host(scan_id))

        port = self.get_scan_ports(scan_id)

        logger.info("%s:%s: Dry run mode.", host, port)

        self.add_scan_log(scan_id, name='', host=host, value='Dry run result')

        self.finish_scan(scan_id)

    def handle_timeout(self, scan_id: str, host: str) -> None:
        """ Handles scanner reaching timeout error. """
        self.add_scan_error(
            scan_id,
            host=host,
            name="Timeout",
            value="{0} exec timeout.".format(self.get_scanner_name()),
        )

    def sort_host_finished(
        self, scan_id: str, finished_hosts: Union[List[str], str]
    ) -> None:
        """Check if the finished host in the list was alive or dead
        and update the corresponding alive_count or dead_count."""
        if isinstance(finished_hosts, str):
            finished_hosts = [finished_hosts]

        alive_hosts = []
        dead_hosts = []

        current_hosts = self.scan_collection.get_current_target_progress(
            scan_id
        )
        for finished_host in finished_hosts:
            progress = current_hosts.get(finished_host)
            if progress == ScanProgress.FINISHED:
                alive_hosts.append(finished_host)
            elif progress == ScanProgress.DEAD_HOST:
                dead_hosts.append(finished_host)
            else:
                logger.debug(
                    'The host %s is considered dead or finished, but '
                    'its progress is still %d. This can lead to '
                    'interrupted scan.',
                    finished_host,
                    progress,
                )

        self.scan_collection.set_host_dead(scan_id, dead_hosts)

        self.scan_collection.set_host_finished(scan_id, alive_hosts)

        self.scan_collection.remove_hosts_from_target_progress(
            scan_id, finished_hosts
        )

    def set_scan_progress(self, scan_id: str):
        """Calculate the target progress with the current host states
        and stores in the scan table."""
        # Get current scan progress for debugging purposes
        logger.debug("Calculating scan progress with the following data:")
        self._get_scan_progress_raw(scan_id)

        scan_progress = self.scan_collection.calculate_target_progress(scan_id)
        self.scan_collection.set_progress(scan_id, scan_progress)

    def set_scan_progress_batch(
        self, scan_id: str, host_progress: Dict[str, int]
    ):
        self.scan_collection.set_host_progress(scan_id, host_progress)
        self.set_scan_progress(scan_id)

    def set_scan_host_progress(
        self, scan_id: str, host: str = None, progress: int = None
    ) -> None:
        """Sets host's progress which is part of target.
        Each time a host progress is updated, the scan progress
        is updated too.
        """
        if host is None or progress is None:
            return

        if not isinstance(progress, int):
            try:
                progress = int(progress)
            except (TypeError, ValueError):
                return

        host_progress = {host: progress}
        self.set_scan_progress_batch(scan_id, host_progress)

    def get_scan_host_progress(self, scan_id: str, host: str = None) -> int:
        """ Get host's progress which is part of target."""
        current_progress = self.scan_collection.get_current_target_progress(
            scan_id
        )
        return current_progress.get(host)

    def set_scan_status(self, scan_id: str, status: ScanStatus) -> None:
        """ Set the scan's status."""
        logger.debug('%s: Set scan status %s,', scan_id, status.name)
        self.scan_collection.set_status(scan_id, status)

    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """ Get scan_id scans's status."""
        status = self.scan_collection.get_status(scan_id)
        logger.debug('%s: Current scan status: %s,', scan_id, status.name)
        return status

    def scan_exists(self, scan_id: str) -> bool:
        """Checks if a scan with ID scan_id is in collection.

        Returns:
            1 if scan exists, 0 otherwise.
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
                    [command_txt, "\t Elements:\n", elements_as_text(elements)]
                )

            txt += command_txt

        return txt

    def delete_scan(self, scan_id: str) -> int:
        """Deletes scan_id scan from collection.

        Returns:
            1 if scan deleted, 0 otherwise.
        """
        if self.get_scan_status(scan_id) == ScanStatus.RUNNING:
            return 0

        # Don't delete the scan until the process stops
        exitcode = None
        try:
            self.scan_processes[scan_id].join()
            exitcode = self.scan_processes[scan_id].exitcode
        except KeyError:
            logger.debug('Scan process for %s never started,', scan_id)

        if exitcode or exitcode == 0:
            del self.scan_processes[scan_id]

        return self.scan_collection.delete_scan(scan_id)

    def get_scan_results_xml(
        self, scan_id: str, pop_res: bool, max_res: Optional[int]
    ):
        """Gets scan_id scan's results in XML format.

        Returns:
            String of scan results in xml.
        """
        results = Element('results')
        for result in self.scan_collection.results_iterator(
            scan_id, pop_res, max_res
        ):
            results.append(get_result_xml(result))

        logger.debug('Returning %d results', len(results))
        return results

    def _get_scan_progress_raw(self, scan_id: str) -> Dict:
        """Returns a dictionary with scan_id scan's progress information."""
        current_progress = dict()

        current_progress[
            'current_hosts'
        ] = self.scan_collection.get_current_target_progress(scan_id)
        current_progress['overall'] = self.get_scan_progress(scan_id)
        current_progress['count_alive'] = self.scan_collection.get_count_alive(
            scan_id
        )
        current_progress['count_dead'] = self.scan_collection.get_count_dead(
            scan_id
        )
        current_progress[
            'count_excluded'
        ] = self.scan_collection.get_simplified_exclude_host_count(scan_id)
        current_progress['count_total'] = self.scan_collection.get_count_total(
            scan_id
        )

        logging.debug(
            "%s: Current progress: \n%s", scan_id, pformat(current_progress)
        )
        return current_progress

    def _get_scan_progress_xml(self, scan_id: str):
        """Gets scan_id scan's progress in XML format.

        Returns:
            String of scan progress in xml.
        """
        current_progress = self._get_scan_progress_raw(scan_id)
        return get_progress_xml(current_progress)

    def get_scan_xml(
        self,
        scan_id: str,
        detailed: bool = True,
        pop_res: bool = False,
        max_res: int = 0,
        progress: bool = False,
    ):
        """Gets scan in XML format.

        Returns:
            String of scan in XML format.
        """
        if not scan_id:
            return Element('scan')

        if self.get_scan_status(scan_id) == ScanStatus.QUEUED:
            target = ''
            scan_progress = 0
            status = self.get_scan_status(scan_id)
            start_time = 0
            end_time = 0
            response = Element('scan')
            detailed = False
            progress = False
            response.append(Element('results'))
        else:
            target = self.get_scan_host(scan_id)
            scan_progress = self.get_scan_progress(scan_id)
            status = self.get_scan_status(scan_id)
            start_time = self.get_scan_start_time(scan_id)
            end_time = self.get_scan_end_time(scan_id)
            response = Element('scan')

        for name, value in [
            ('id', scan_id),
            ('target', target),
            ('progress', scan_progress),
            ('status', status.name.lower()),
            ('start_time', start_time),
            ('end_time', end_time),
        ]:
            response.set(name, str(value))
        if detailed:
            response.append(
                self.get_scan_results_xml(scan_id, pop_res, max_res)
            )
        if progress:
            response.append(self._get_scan_progress_xml(scan_id))

        return response

    @staticmethod
    def get_custom_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, custom: Dict
    ) -> str:
        """Create a string representation of the XML object from the
        custom data object.
        This needs to be implemented by each ospd wrapper, in case
        custom elements for VTs are used.

        The custom XML object which is returned will be embedded
        into a <custom></custom> element.

        Returns:
            XML object as string for custom data.
        """
        return ''

    @staticmethod
    def get_params_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_params
    ) -> str:
        """Create a string representation of the XML object from the
        vt_params data object.
        This needs to be implemented by each ospd wrapper, in case
        vt_params elements for VTs are used.

        The params XML object which is returned will be embedded
        into a <params></params> element.

        Returns:
            XML object as string for vt parameters data.
        """
        return ''

    @staticmethod
    def get_refs_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_refs
    ) -> str:
        """Create a string representation of the XML object from the
        refs data object.
        This needs to be implemented by each ospd wrapper, in case
        refs elements for VTs are used.

        The refs XML object which is returned will be embedded
        into a <refs></refs> element.

        Returns:
            XML object as string for vt references data.
        """
        return ''

    @staticmethod
    def get_dependencies_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_dependencies
    ) -> str:
        """Create a string representation of the XML object from the
        vt_dependencies data object.
        This needs to be implemented by each ospd wrapper, in case
        vt_dependencies elements for VTs are used.

        The vt_dependencies XML object which is returned will be embedded
        into a <dependencies></dependencies> element.

        Returns:
            XML object as string for vt dependencies data.
        """
        return ''

    @staticmethod
    def get_creation_time_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_creation_time
    ) -> str:
        """Create a string representation of the XML object from the
        vt_creation_time data object.
        This needs to be implemented by each ospd wrapper, in case
        vt_creation_time elements for VTs are used.

        The vt_creation_time XML object which is returned will be embedded
        into a <vt_creation_time></vt_creation_time> element.

        Returns:
            XML object as string for vt creation time data.
        """
        return ''

    @staticmethod
    def get_modification_time_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, vt_modification_time
    ) -> str:
        """Create a string representation of the XML object from the
        vt_modification_time data object.
        This needs to be implemented by each ospd wrapper, in case
        vt_modification_time elements for VTs are used.

        The vt_modification_time XML object which is returned will be embedded
        into a <vt_modification_time></vt_modification_time> element.

        Returns:
            XML object as string for vt references data.
        """
        return ''

    @staticmethod
    def get_summary_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, summary
    ) -> str:
        """Create a string representation of the XML object from the
        summary data object.
        This needs to be implemented by each ospd wrapper, in case
        summary elements for VTs are used.

        The summary XML object which is returned will be embedded
        into a <summary></summary> element.

        Returns:
            XML object as string for summary data.
        """
        return ''

    @staticmethod
    def get_impact_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, impact
    ) -> str:
        """Create a string representation of the XML object from the
        impact data object.
        This needs to be implemented by each ospd wrapper, in case
        impact elements for VTs are used.

        The impact XML object which is returned will be embedded
        into a <impact></impact> element.

        Returns:
            XML object as string for impact data.
        """
        return ''

    @staticmethod
    def get_affected_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, affected
    ) -> str:
        """Create a string representation of the XML object from the
        affected data object.
        This needs to be implemented by each ospd wrapper, in case
        affected elements for VTs are used.

        The affected XML object which is returned will be embedded
        into a <affected></affected> element.

        Returns:
            XML object as string for affected data.
        """
        return ''

    @staticmethod
    def get_insight_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, insight
    ) -> str:
        """Create a string representation of the XML object from the
        insight data object.
        This needs to be implemented by each ospd wrapper, in case
        insight elements for VTs are used.

        The insight XML object which is returned will be embedded
        into a <insight></insight> element.

        Returns:
            XML object as string for insight data.
        """
        return ''

    @staticmethod
    def get_solution_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, solution, solution_type=None, solution_method=None
    ) -> str:
        """Create a string representation of the XML object from the
        solution data object.
        This needs to be implemented by each ospd wrapper, in case
        solution elements for VTs are used.

        The solution XML object which is returned will be embedded
        into a <solution></solution> element.

        Returns:
            XML object as string for solution data.
        """
        return ''

    @staticmethod
    def get_detection_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, detection=None, qod_type=None, qod=None
    ) -> str:
        """Create a string representation of the XML object from the
        detection data object.
        This needs to be implemented by each ospd wrapper, in case
        detection elements for VTs are used.

        The detection XML object which is returned is an element with
        tag <detection></detection> element

        Returns:
            XML object as string for detection data.
        """
        return ''

    @staticmethod
    def get_severities_vt_as_xml_str(  # pylint: disable=unused-argument
        vt_id: str, severities
    ) -> str:
        """Create a string representation of the XML object from the
        severities data object.
        This needs to be implemented by each ospd wrapper, in case
        severities elements for VTs are used.

        The severities XML objects which are returned will be embedded
        into a <severities></severities> element.

        Returns:
            XML object as string for severities data.
        """
        return ''

    def get_vt_iterator(  # pylint: disable=unused-argument
        self, vt_selection: List[str] = None, details: bool = True
    ) -> Iterator[Tuple[str, Dict]]:
        """Return iterator object for getting elements
        from the VTs dictionary."""
        return self.vts.items()

    def get_vt_xml(self, single_vt: Tuple[str, Dict]) -> Element:
        """Gets a single vulnerability test information in XML format.

        Returns:
            String of single vulnerability test information in XML format.
        """
        if not single_vt or single_vt[1] is None:
            return Element('vt')

        vt_id, vt = single_vt

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
    ) -> Iterable[str]:
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

        Returns:
            List of selected VT's OID.
        """
        vts_xml = []

        # No match for the filter
        if filtered_vts is not None and len(filtered_vts) == 0:
            return vts_xml

        if filtered_vts:
            vts_list = filtered_vts
        elif vt_id:
            vts_list = [vt_id]
        else:
            vts_list = self.vts.keys()

        return vts_list

    def handle_command(self, data: bytes, stream: Stream) -> None:
        """Handles an osp command in a string."""
        try:
            tree = secET.fromstring(data)
        except secET.ParseError as e:
            logger.debug("Erroneous client input: %s", data)
            raise OspdCommandError('Invalid data') from e

        command_name = tree.tag

        logger.debug('Handling %s command request.', command_name)

        command = self.commands.get(command_name, None)
        if not command and command_name != "authenticate":
            raise OspdCommandError('Bogus command name')

        if not self.initialized and command.must_be_initialized:
            exception = OspdCommandError(
                '%s is still starting' % self.daemon_info['name'], 'error'
            )
            response = exception.as_xml()
            stream.write(response)
            return

        response = command.handle_xml(tree)

        write_success = True
        if isinstance(response, bytes):
            write_success = stream.write(response)
        else:
            for data in response:
                write_success = stream.write(data)
                if not write_success:
                    break

        scan_id = tree.get('scan_id')
        if self.scan_exists(scan_id) and command_name == "get_scans":
            if write_success:
                logger.debug(
                    '%s: Results sent successfully to the client. Cleaning '
                    'temporary result list.',
                    scan_id,
                )
                self.scan_collection.clean_temp_result_list(scan_id)
            else:
                logger.debug(
                    '%s: Failed sending results to the client. Restoring '
                    'result list into the cache.',
                    scan_id,
                )
                self.scan_collection.restore_temp_result_list(scan_id)

    def check(self):
        """ Asserts to False. Should be implemented by subclass. """
        raise NotImplementedError

    def run(self) -> None:
        """Starts the Daemon, handling commands until interrupted."""

        try:
            while True:
                time.sleep(SCHEDULER_CHECK_PERIOD)
                self.scheduler()
                self.clean_forgotten_scans()
                self.start_queued_scans()
                self.wait_for_children()
        except KeyboardInterrupt:
            logger.info("Received Ctrl-C shutting-down ...")

    def start_queued_scans(self) -> None:
        """ Starts a queued scan if it is allowed """

        current_queued_scans = self.get_count_queued_scans()
        if not current_queued_scans:
            return

        if not self.initialized:
            logger.info(
                "Queued task can not be started because a feed "
                "update is being performed."
            )
            return

        logger.info('Currently %d queued scans.', current_queued_scans)

        for scan_id in self.scan_collection.ids_iterator():
            scan_allowed = (
                self.is_new_scan_allowed() and self.is_enough_free_memory()
            )
            scan_is_queued = self.get_scan_status(scan_id) == ScanStatus.QUEUED

            if scan_is_queued and scan_allowed:
                try:
                    self.scan_collection.unpickle_scan_info(scan_id)
                except OspdCommandError as e:
                    logger.error("Start scan error %s", e)
                    self.stop_scan(scan_id)
                    continue

                scan_func = self.start_scan
                scan_process = create_process(func=scan_func, args=(scan_id,))
                self.scan_processes[scan_id] = scan_process
                scan_process.start()
                self.set_scan_status(scan_id, ScanStatus.INIT)

                current_queued_scans = current_queued_scans - 1
                self.last_scan_start_time = time.time()
                logger.info('Starting scan %s.', scan_id)
            elif scan_is_queued and not scan_allowed:
                return

    def is_new_scan_allowed(self) -> bool:
        """Check if max_scans has been reached.

        Returns:
            True if a new scan can be launch.
        """
        if (self.max_scans != 0) and (
            len(self.scan_processes) >= self.max_scans
        ):
            logger.info(
                'Not possible to run a new scan. Max scan limit set '
                'to %d reached.',
                self.max_scans,
            )
            return False

        return True

    def is_enough_free_memory(self) -> bool:
        """Check if there is enough free memory in the system to run
        a new scan. The necessary memory is a rough calculation and very
        conservative.

        Returns:
            True if there is enough memory for a new scan.
        """
        if not self.min_free_mem_scan_queue:
            return True

        # If min_free_mem_scan_queue option is set, also wait some time
        # between scans. Consider the case in which the last scan
        # finished in a few seconds and there is no need to wait.
        time_between_start_scan = time.time() - self.last_scan_start_time
        if (
            time_between_start_scan < MIN_TIME_BETWEEN_START_SCAN
            and self.get_count_running_scans()
        ):
            logger.debug(
                'Not possible to run a new scan right now, a scan have been '
                'just started.'
            )
            return False

        free_mem = psutil.virtual_memory().available / (1024 * 1024)

        if free_mem > self.min_free_mem_scan_queue:
            return True

        logger.info(
            'Not possible to run a new scan. Not enough free memory. '
            'Only %d MB available but at least %d are required',
            free_mem,
            self.min_free_mem_scan_queue,
        )

        return False

    def scheduler(self):
        """Should be implemented by subclass in case of need
        to run tasks periodically."""

    def wait_for_children(self):
        """ Join the zombie process to releases resources."""
        for scan_id, _ in self.scan_processes.items():
            self.scan_processes[scan_id].join(0)

    def create_scan(
        self,
        scan_id: str,
        targets: Dict,
        options: Optional[Dict],
        vt_selection: Dict,
    ) -> Optional[str]:
        """Creates a new scan.

        Arguments:
            target: Target to scan.
            options: Miscellaneous scan options supplied via <scanner_params>
                  XML element.

        Returns:
            New scan's ID. None if the scan_id already exists.
        """
        status = None
        scan_exists = self.scan_exists(scan_id)
        if scan_id and scan_exists:
            status = self.get_scan_status(scan_id)
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

    def set_scan_total_hosts(self, scan_id: str, count_total: int) -> None:
        """Sets a scan's total hosts. Allow the scanner to update
        the total count of host to be scanned."""
        self.scan_collection.update_count_total(scan_id, count_total)

    def clean_forgotten_scans(self) -> None:
        """Check for old stopped or finished scans which have not been
        deleted and delete them if the are older than the set value."""

        if not self.scaninfo_store_time:
            return

        for scan_id in list(self.scan_collection.ids_iterator()):
            end_time = int(self.get_scan_end_time(scan_id))
            scan_status = self.get_scan_status(scan_id)

            if (
                scan_status == ScanStatus.STOPPED
                or scan_status == ScanStatus.FINISHED
                or scan_status == ScanStatus.INTERRUPTED
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
        status = self.get_scan_status(scan_id)
        if status == ScanStatus.QUEUED:
            return

        scan_process = self.scan_processes.get(scan_id)
        progress = self.get_scan_progress(scan_id)

        if (
            progress < ScanProgress.FINISHED
            and scan_process
            and not scan_process.is_alive()
        ):
            if not status == ScanStatus.STOPPED:
                self.add_scan_error(
                    scan_id, name="", host="", value="Scan process Failure"
                )

                logger.info(
                    "%s: Scan process is dead and its progress is %d",
                    scan_id,
                    progress,
                )
                self.interrupt_scan(scan_id)

        elif progress == ScanProgress.FINISHED:
            scan_process.join(0)

        logger.debug(
            "%s: Check scan process: \n\tProgress %d\n\t Status: %s",
            scan_id,
            progress,
            status.name,
        )

    def get_count_queued_scans(self) -> int:
        """ Get the amount of scans with queued status """
        count = 0
        for scan_id in self.scan_collection.ids_iterator():
            if self.get_scan_status(scan_id) == ScanStatus.QUEUED:
                count += 1
        return count

    def get_count_running_scans(self) -> int:
        """ Get the amount of scans with INIT/RUNNING status """
        count = 0
        for scan_id in self.scan_collection.ids_iterator():
            status = self.get_scan_status(scan_id)
            if status == ScanStatus.RUNNING or status == ScanStatus.INIT:
                count += 1
        return count

    def get_scan_progress(self, scan_id: str) -> int:
        """ Gives a scan's current progress value. """
        progress = self.scan_collection.get_progress(scan_id)
        logger.debug('%s: Current scan progress: %s,', scan_id, progress)
        return progress

    def get_scan_host(self, scan_id: str) -> str:
        """ Gives a scan's target. """
        return self.scan_collection.get_host_list(scan_id)

    def get_scan_ports(self, scan_id: str) -> str:
        """ Gives a scan's ports list. """
        return self.scan_collection.get_ports(scan_id)

    def get_scan_exclude_hosts(self, scan_id: str):
        """Gives a scan's exclude host list. If a target is passed gives
        the exclude host list for the given target."""
        return self.scan_collection.get_exclude_hosts(scan_id)

    def get_scan_credentials(self, scan_id: str) -> Dict:
        """Gives a scan's credential list. If a target is passed gives
        the credential list for the given target."""
        return self.scan_collection.get_credentials(scan_id)

    def get_scan_target_options(self, scan_id: str) -> Dict:
        """Gives a scan's target option dict. If a target is passed gives
        the credential list for the given target."""
        return self.scan_collection.get_target_options(scan_id)

    def get_scan_vts(self, scan_id: str) -> Dict:
        """ Gives a scan's vts. """
        return self.scan_collection.get_vts(scan_id)

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
        uri: str = '',
    ) -> None:
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
            uri,
        )

    def add_scan_error(
        self,
        scan_id: str,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id='',
        uri: str = '',
    ) -> None:
        """ Adds an error result to scan_id scan. """
        self.scan_collection.add_result(
            scan_id,
            ResultType.ERROR,
            host,
            hostname,
            name,
            value,
            port,
            test_id,
            uri,
        )

    def add_scan_host_detail(
        self,
        scan_id: str,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        uri: str = '',
    ) -> None:
        """ Adds a host detail result to scan_id scan. """
        self.scan_collection.add_result(
            scan_id, ResultType.HOST_DETAIL, host, hostname, name, value, uri
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
        uri: str = '',
    ) -> None:
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
            uri,
        )
