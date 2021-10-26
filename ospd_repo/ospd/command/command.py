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

import multiprocessing
import re
import logging
import subprocess

from decimal import Decimal
from typing import Optional, Dict, Any, Union, Iterator

from xml.etree.ElementTree import Element, SubElement

import psutil

from ospd.errors import OspdCommandError
from ospd.misc import valid_uuid, create_process
from ospd.protocol import OspRequest, OspResponse
from ospd.xml import (
    simple_response_str,
    get_elements_from_dict,
    XmlStringHelper,
)

from .initsubclass import InitSubclassMeta
from .registry import register_command

logger = logging.getLogger(__name__)


class BaseCommand(metaclass=InitSubclassMeta):

    name = None
    description = None
    attributes = None
    elements = None
    must_be_initialized = None

    def __init_subclass__(cls, **kwargs):
        super_cls = super()

        if hasattr(super_cls, '__init_subclass__'):
            super_cls.__init_subclass__(**kwargs)

        register_command(cls)

    def __init__(self, daemon):
        self._daemon = daemon

    def get_name(self) -> str:
        return self.name

    def get_description(self) -> str:
        return self.description

    def get_attributes(self) -> Optional[Dict[str, Any]]:
        return self.attributes

    def get_elements(self) -> Optional[Dict[str, Any]]:
        return self.elements

    def handle_xml(self, xml: Element) -> Union[bytes, Iterator[bytes]]:
        raise NotImplementedError()

    def as_dict(self):
        return {
            'name': self.get_name(),
            'attributes': self.get_attributes(),
            'description': self.get_description(),
            'elements': self.get_elements(),
        }

    def __repr__(self):
        return '<{} description="{}" attributes={} elements={}>'.format(
            self.name, self.description, self.attributes, self.elements
        )


class HelpCommand(BaseCommand):
    name = "help"
    description = 'Print the commands help.'
    attributes = {'format': 'Help format. Could be text or xml.'}
    must_be_initialized = False

    def handle_xml(self, xml: Element) -> bytes:
        help_format = xml.get('format')

        if help_format is None or help_format == "text":
            # Default help format is text.
            return simple_response_str(
                'help', 200, 'OK', self._daemon.get_help_text()
            )
        elif help_format == "xml":
            text = get_elements_from_dict(
                {k: v.as_dict() for k, v in self._daemon.commands.items()}
            )
            return simple_response_str('help', 200, 'OK', text)

        raise OspdCommandError('Bogus help format', 'help')


class GetVersion(BaseCommand):
    name = "get_version"
    description = 'Return various version information'
    must_be_initialized = False

    def handle_xml(self, xml: Element) -> bytes:
        """Handles <get_version> command.

        Return:
            Response string for <get_version> command.
        """
        protocol = Element('protocol')

        for name, value in [
            ('name', 'OSP'),
            ('version', self._daemon.get_protocol_version()),
        ]:
            elem = SubElement(protocol, name)
            elem.text = value

        daemon = Element('daemon')
        for name, value in [
            ('name', self._daemon.get_daemon_name()),
            ('version', self._daemon.get_daemon_version()),
        ]:
            elem = SubElement(daemon, name)
            elem.text = value

        scanner = Element('scanner')
        for name, value in [
            ('name', self._daemon.get_scanner_name()),
            ('version', self._daemon.get_scanner_version()),
        ]:
            elem = SubElement(scanner, name)
            elem.text = value

        content = [protocol, daemon, scanner]

        vts_version = self._daemon.get_vts_version()
        if vts_version:
            vts = Element('vts')
            elem = SubElement(vts, 'version')
            elem.text = vts_version
            content.append(vts)

        return simple_response_str('get_version', 200, 'OK', content)


GVMCG_TITLES = [
    'cpu-.*',
    'proc',
    'mem',
    'swap',
    'load',
    'df-.*',
    'disk-sd[a-z][0-9]-rw',
    'disk-sd[a-z][0-9]-load',
    'disk-sd[a-z][0-9]-io-load',
    'interface-eth.*-traffic',
    'interface-eth.*-err-rate',
    'interface-eth.*-err',
    'sensors-.*_temperature-.*',
    'sensors-.*_fanspeed-.*',
    'sensors-.*_voltage-.*',
    'titles',
]  # type: List[str]


class GetPerformance(BaseCommand):
    name = "get_performance"
    description = 'Return system report'
    attributes = {
        'start': 'Time of first data point in report.',
        'end': 'Time of last data point in report.',
        'title': 'Name of report.',
    }
    must_be_initialized = False

    def handle_xml(self, xml: Element) -> bytes:
        """Handles <get_performance> command.

        @return: Response string for <get_performance> command.
        """
        start = xml.attrib.get('start')
        end = xml.attrib.get('end')
        titles = xml.attrib.get('titles')

        cmd = ['gvmcg']
        if start:
            try:
                int(start)
            except ValueError:
                raise OspdCommandError(
                    'Start argument must be integer.', 'get_performance'
                ) from None

            cmd.append(start)

        if end:
            try:
                int(end)
            except ValueError:
                raise OspdCommandError(
                    'End argument must be integer.', 'get_performance'
                ) from None

            cmd.append(end)

        if titles:
            combined = "(" + ")|(".join(GVMCG_TITLES) + ")"
            forbidden = "^[^|&;]+$"
            if re.match(combined, titles) and re.match(forbidden, titles):
                cmd.append(titles)
            else:
                raise OspdCommandError(
                    'Arguments not allowed', 'get_performance'
                )

        try:
            output = subprocess.check_output(cmd)
        except (subprocess.CalledProcessError, OSError) as e:
            raise OspdCommandError(
                'Bogus get_performance format. %s' % e, 'get_performance'
            ) from None

        return simple_response_str(
            'get_performance', 200, 'OK', output.decode()
        )


class GetScannerDetails(BaseCommand):
    name = 'get_scanner_details'
    description = 'Return scanner description and parameters'
    must_be_initialized = True

    def handle_xml(self, xml: Element) -> bytes:
        """Handles <get_scanner_details> command.

        @return: Response string for <get_scanner_details> command.
        """
        list_all = xml.get('list_all')
        list_all = True if list_all == '1' else False

        desc_xml = Element('description')
        desc_xml.text = self._daemon.get_scanner_description()
        scanner_params = self._daemon.get_scanner_params()

        if not list_all:
            scanner_params = {
                key: value
                for (key, value) in scanner_params.items()
                if value.get('visible_for_client')
            }

        details = [
            desc_xml,
            OspResponse.create_scanner_params_xml(scanner_params),
        ]
        return simple_response_str('get_scanner_details', 200, 'OK', details)


class DeleteScan(BaseCommand):
    name = 'delete_scan'
    description = 'Delete a finished scan.'
    attributes = {'scan_id': 'ID of scan to delete.'}
    must_be_initialized = False

    def handle_xml(self, xml: Element) -> bytes:
        """Handles <delete_scan> command.

        @return: Response string for <delete_scan> command.
        """
        scan_id = xml.get('scan_id')
        if scan_id is None:
            return simple_response_str(
                'delete_scan', 404, 'No scan_id attribute'
            )

        if not self._daemon.scan_exists(scan_id):
            text = "Failed to find scan '{0}'".format(scan_id)
            return simple_response_str('delete_scan', 404, text)

        self._daemon.check_scan_process(scan_id)

        if self._daemon.delete_scan(scan_id):
            return simple_response_str('delete_scan', 200, 'OK')

        raise OspdCommandError('Scan in progress', 'delete_scan')


class GetVts(BaseCommand):
    name = 'get_vts'
    description = 'List of available vulnerability tests.'
    attributes = {
        'vt_id': 'ID of a specific vulnerability test to get.',
        'filter': 'Optional filter to get an specific vt collection.',
    }
    must_be_initialized = True

    def handle_xml(self, xml: Element) -> Iterator[bytes]:
        """Handles <get_vts> command.
        Writes the vt collection on the stream.
        The <get_vts> element accept two optional arguments.
        vt_id argument receives a single vt id.
        filter argument receives a filter selecting a sub set of vts.
        If both arguments are given, the vts which match with the filter
        are return.

        @return: Response string for <get_vts> command on fail.
        """
        self._daemon.vts.is_cache_available = False

        xml_helper = XmlStringHelper()

        vt_id = xml.get('vt_id')
        vt_filter = xml.get('filter')
        _details = xml.get('details')
        version_only = xml.get('version_only')

        vt_details = False if _details == '0' else True

        if self._daemon.vts and vt_id and vt_id not in self._daemon.vts:
            self._daemon.vts.is_cache_available = True
            text = "Failed to find vulnerability test '{0}'".format(vt_id)
            raise OspdCommandError(text, 'get_vts', 404)

        filtered_vts = None
        if vt_filter and not version_only:
            try:
                filtered_vts = self._daemon.vts_filter.get_filtered_vts_list(
                    self._daemon.vts, vt_filter
                )
            except OspdCommandError as filter_error:
                self._daemon.vts.is_cache_available = True
                raise filter_error

        if not version_only:
            vts_selection = self._daemon.get_vts_selection_list(
                vt_id, filtered_vts
            )
        # List of xml pieces with the generator to be iterated
        yield xml_helper.create_response('get_vts')

        begin_vts_tag = xml_helper.create_element('vts')
        begin_vts_tag = xml_helper.add_attr(
            begin_vts_tag, "vts_version", self._daemon.get_vts_version()
        )
        val = len(self._daemon.vts)
        begin_vts_tag = xml_helper.add_attr(begin_vts_tag, "total", val)
        if filtered_vts and not version_only:
            val = len(filtered_vts)
            begin_vts_tag = xml_helper.add_attr(begin_vts_tag, "sent", val)

        if self._daemon.vts.sha256_hash is not None:
            begin_vts_tag = xml_helper.add_attr(
                begin_vts_tag, "sha256_hash", self._daemon.vts.sha256_hash
            )

        yield begin_vts_tag
        if not version_only:
            for vt in self._daemon.get_vt_iterator(vts_selection, vt_details):
                yield xml_helper.add_element(self._daemon.get_vt_xml(vt))

        yield xml_helper.create_element('vts', end=True)
        yield xml_helper.create_response('get_vts', end=True)

        self._daemon.vts.is_cache_available = True


class StopScan(BaseCommand):
    name = 'stop_scan'
    description = 'Stop a currently running scan.'
    attributes = {'scan_id': 'ID of scan to stop.'}
    must_be_initialized = True

    def handle_xml(self, xml: Element) -> bytes:
        """Handles <stop_scan> command.

        @return: Response string for <stop_scan> command.
        """

        scan_id = xml.get('scan_id')
        if scan_id is None or scan_id == '':
            raise OspdCommandError('No scan_id attribute', 'stop_scan')

        self._daemon.stop_scan(scan_id)

        # Don't send response until the scan is stopped.
        try:
            self._daemon.scan_processes[scan_id].join()
        except KeyError:
            pass

        return simple_response_str('stop_scan', 200, 'OK')


class GetScans(BaseCommand):
    name = 'get_scans'
    description = 'Get information about a scan in buffer.'
    attributes = {
        'scan_id': 'Mandatory ID of a specific scan to get.',
        'details': 'Whether to return the full scan report.',
        'pop_results': 'Whether to remove the fetched results.',
        'max_results': 'Maximum number of results to fetch.',
        'progress': 'Whether to return a detailed scan progress',
    }
    must_be_initialized = False

    def handle_xml(self, xml: Element) -> bytes:
        """Handles <get_scans> command.

        @return: Response string for <get_scans> command.
        """

        scan_id = xml.get('scan_id')
        if scan_id is None or scan_id == '':
            raise OspdCommandError('No scan_id attribute', 'get_scans')

        details = xml.get('details')
        pop_res = xml.get('pop_results')
        max_res = xml.get('max_results')
        progress = xml.get('progress')

        if details and details == '0':
            details = False
        else:
            details = True
            pop_res = pop_res and pop_res == '1'

            if max_res:
                max_res = int(max_res)

        progress = progress and progress == '1'

        responses = []
        if scan_id in self._daemon.scan_collection.ids_iterator():
            self._daemon.check_scan_process(scan_id)
            scan = self._daemon.get_scan_xml(
                scan_id, details, pop_res, max_res, progress
            )
            responses.append(scan)
        else:
            text = "Failed to find scan '{0}'".format(scan_id)
            return simple_response_str('get_scans', 404, text)

        return simple_response_str('get_scans', 200, 'OK', responses)


class StartScan(BaseCommand):
    name = 'start_scan'
    description = 'Start a new scan.'
    attributes = {
        'target': 'Target host to scan',
        'ports': 'Ports list to scan',
        'scan_id': 'Optional UUID value to use as scan ID',
        'parallel': 'Optional nummer of parallel target to scan',
    }
    must_be_initialized = False

    def get_elements(self):
        elements = {}

        if self.elements:
            elements.update(self.elements)

        scanner_params = elements.get('scanner_params', {}).copy()
        elements['scanner_params'] = scanner_params

        scanner_params.update(
            {
                k: v['description']
                for k, v in self._daemon.scanner_params.items()
            }
        )

        return elements

    def handle_xml(self, xml: Element) -> bytes:
        """Handles <start_scan> command.

        Return:
            Response string for <start_scan> command.
        """

        current_queued_scans = self._daemon.get_count_queued_scans()
        if (
            self._daemon.max_queued_scans
            and current_queued_scans >= self._daemon.max_queued_scans
        ):
            logger.info(
                'Maximum number of queued scans set to %d reached.',
                self._daemon.max_queued_scans,
            )
            raise OspdCommandError(
                'Maximum number of queued scans set to %d reached.'
                % self._daemon.max_queued_scans,
                'start_scan',
            )

        target_str = xml.get('target')
        ports_str = xml.get('ports')

        # For backward compatibility, if target and ports attributes are set,
        # <targets> element is ignored.
        if target_str is None or ports_str is None:
            target_element = xml.find('targets/target')
            if target_element is None:
                raise OspdCommandError('No targets or ports', 'start_scan')
            else:
                scan_target = OspRequest.process_target_element(target_element)
        else:
            scan_target = {
                'hosts': target_str,
                'ports': ports_str,
                'credentials': {},
                'exclude_hosts': '',
                'finished_hosts': '',
                'options': {},
            }
            logger.warning(
                "Legacy start scan command format is being used, which "
                "is deprecated since 20.08. Please read the documentation "
                "for start scan command."
            )

        scan_id = xml.get('scan_id')
        if scan_id is not None and scan_id != '' and not valid_uuid(scan_id):
            raise OspdCommandError('Invalid scan_id UUID', 'start_scan')

        if xml.get('parallel'):
            logger.warning(
                "parallel attribute of start_scan will be ignored, sice "
                "parallel scan is not supported by OSPd."
            )

        scanner_params = xml.find('scanner_params')
        if scanner_params is None:
            raise OspdCommandError('No scanner_params element', 'start_scan')

        # params are the parameters we got from the <scanner_params> XML.
        params = self._daemon.preprocess_scan_params(scanner_params)

        # VTS is an optional element. If present should not be empty.
        vt_selection = {}  # type: Dict
        scanner_vts = xml.find('vt_selection')
        if scanner_vts is not None:
            if len(scanner_vts) == 0:
                raise OspdCommandError('VTs list is empty', 'start_scan')
            else:
                vt_selection = OspRequest.process_vts_params(scanner_vts)

        # Dry run case.
        dry_run = 'dry_run' in params and int(params['dry_run'])
        if dry_run:
            scan_params = None
        else:
            scan_params = self._daemon.process_scan_params(params)

        scan_id_aux = scan_id
        scan_id = self._daemon.create_scan(
            scan_id, scan_target, scan_params, vt_selection
        )

        if not scan_id:
            id_ = Element('id')
            id_.text = scan_id_aux
            return simple_response_str('start_scan', 100, 'Continue', id_)

        logger.info(
            'Scan %s added to the queue in position %d.',
            scan_id,
            current_queued_scans + 1,
        )

        if dry_run:
            scan_func = self._daemon.dry_run_scan
            scan_process = create_process(
                func=scan_func, args=(scan_id, scan_target)
            )
            self._daemon.scan_processes[scan_id] = scan_process
            scan_process.start()

        id_ = Element('id')
        id_.text = scan_id

        return simple_response_str('start_scan', 200, 'OK', id_)


class GetMemoryUsage(BaseCommand):

    name = "get_memory_usage"
    description = "print the memory consumption of all processes"
    attributes = {
        'unit': 'Unit for displaying memory consumption (b = bytes, '
        'kb = kilobytes, mb = megabytes). Defaults to b.'
    }
    must_be_initialized = False

    @staticmethod
    def _get_memory(value: int, unit: str = None) -> str:
        if not unit:
            return str(value)

        unit = unit.lower()

        if unit == 'kb':
            return str(Decimal(value) / 1024)

        if unit == 'mb':
            return str(Decimal(value) / (1024 * 1024))

        return str(value)

    @staticmethod
    def _create_process_element(name: str, pid: int):
        process_element = Element('process')
        process_element.set('name', name)
        process_element.set('pid', str(pid))

        return process_element

    @classmethod
    def _add_memory_info(
        cls, process_element: Element, pid: int, unit: str = None
    ):
        try:
            ps_process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return

        memory = ps_process.memory_info()

        rss_element = Element('rss')
        rss_element.text = cls._get_memory(memory.rss, unit)

        process_element.append(rss_element)

        vms_element = Element('vms')
        vms_element.text = cls._get_memory(memory.vms, unit)

        process_element.append(vms_element)

        shared_element = Element('shared')
        shared_element.text = cls._get_memory(memory.shared, unit)

        process_element.append(shared_element)

    def handle_xml(self, xml: Element) -> bytes:
        processes_element = Element('processes')
        unit = xml.get('unit')

        current_process = multiprocessing.current_process()
        process_element = self._create_process_element(
            current_process.name, current_process.pid
        )

        self._add_memory_info(process_element, current_process.pid, unit)

        processes_element.append(process_element)

        for proc in multiprocessing.active_children():
            process_element = self._create_process_element(proc.name, proc.pid)

            self._add_memory_info(process_element, proc.pid, unit)

            processes_element.append(process_element)

        return simple_response_str('get_memory', 200, 'OK', processes_element)
