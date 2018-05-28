# -*- coding: utf-8 -*-
# $Id$
# Description:
# OSP Daemon core class.
#
# Authors:
# Hani Benhabiles <hani.benhabiles@greenbone.net>
# Benoît Allard <benoit.allard@greenbone.net>
#
# Copyright:
# Copyright (C) 2014, 2015 Greenbone Networks GmbH
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

""" OSP Daemon core class. """

# This is needed for older pythons as our current module is called the same
# as the package we are in ...
# Another solution would be to rename that file.
from __future__ import absolute_import

import logging
import socket
import ssl
import multiprocessing
import xml.etree.ElementTree as ET
import os

from ospd import __version__
from ospd.misc import ScanCollection, ResultType, target_str_to_list
from ospd.misc import resolve_hostname, valid_uuid

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "1.1"

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
        },
        'elements': None
    },
    'stop_scan': {
        'description': 'Stop a currently running scan.',
        'attributes': {
            'scan_id': 'ID of scan to stop.'
        },
        'elements': None
    },
    'help': {
        'description': 'Print the commands help.',
        'attributes': {
            'format': 'Help format. Could be text or xml.'
        },
        'elements': None
    },
    'get_scans': {
        'description': 'List the scans in buffer.',
        'attributes': {
            'scan_id': 'ID of a specific scan to get.',
            'details': 'Whether to return the full scan report.'
        },
        'elements': None
    },
    'delete_scan': {
        'description': 'Delete a finished scan.',
        'attributes': {
            'scan_id': 'ID of scan to delete.'
        },
        'elements': None
    },
    'get_version': {
        'description': 'Return various versions.',
        'attributes': None,
        'elements': None
    },
    'get_scanner_details': {
        'description': 'Return scanner description and parameters',
        'attributes': None,
        'elements': None
    }
}


def get_result_xml(result):
    """ Formats a scan result to XML format. """
    result_xml = ET.Element('result')
    for name, value in [('name', result['name']),
                        ('type', ResultType.get_str(result['type'])),
                        ('severity', result['severity']),
                        ('host', result['host']),
                        ('test_id', result['test_id']),
                        ('port', result['port']),
                        ('qod', result['qod'])]:
        result_xml.set(name, str(value))
    result_xml.text = result['value']
    return result_xml


def simple_response_str(command, status, status_text, content=""):
    """ Creates an OSP response XML string.

    @param: OSP Command to respond to.
    @param: Status of the response.
    @param: Status text of the response.
    @param: Text part of the response XML element.

    @return: String of response in xml format.
    """
    response = ET.Element('%s_response' % command)
    for name, value in [('status', str(status)), ('status_text', status_text)]:
        response.set(name, str(value))
    if isinstance(content, list):
        for elem in content:
            response.append(elem)
    elif isinstance(content, ET.Element):
        response.append(content)
    else:
        response.text = content
    return ET.tostring(response)


class OSPDError(Exception):

    """ This is an exception that will result in an error message to the
    client """

    def __init__(self, message, command='osp', status=400):
        super(OSPDError, self).__init__()
        self.message = message
        self.command = command
        self.status = status

    def as_xml(self):
        """ Return the error in xml format. """
        return simple_response_str(self.command, self.status, self.message)


def bind_socket(address, port):
    """ Returns a socket bound on (address:port). """

    assert address
    assert port
    bindsocket = socket.socket()
    try:
        bindsocket.bind((address, port))
    except socket.error:
        logger.error("Couldn't bind socket on {0}:{1}"
                     .format(address, port))
        return None

    logger.info('Listening on {0}:{1}'.format(address, port))
    bindsocket.listen(0)
    return bindsocket

def bind_unix_socket(path):
    """ Returns a unix file socket bound on (path). """

    assert path
    bindsocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(path)
    except OSError:
        if os.path.exists(path):
            raise
    try:
        bindsocket.bind(path)
    except socket.error:
        logger.error("Couldn't bind socket on {0}".format(path))
        return None

    logger.info('Listening on {0}'.format(path))
    bindsocket.listen(0)
    return bindsocket


def close_client_stream(client_stream, unix_path):
    """ Closes provided client stream """
    try:
        client_stream.shutdown(socket.SHUT_RDWR)
        if unix_path:
            logger.debug('{0}: Connection closed'.format(unix_path))
        else:
            peer = client_stream.getpeername()
            logger.debug('{0}:{1}: Connection closed'.format(peer[0], peer[1]))
    except (socket.error, OSError) as exception:
        logger.debug('Connection closing error: {0}'.format(exception))
    client_stream.close()


class OSPDaemon(object):

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

    def __init__(self, certfile, keyfile, cafile):
        """ Initializes the daemon's internal data. """
        # @todo: Actually it makes sense to move the certificate params to
        #        a separate function because it is not mandatory anymore to
        #        use a TLS setup (unix file socket is an alternative).
        #        However, changing this makes it mandatory for any ospd scanner
        #        to change the function calls as well. So this breaks the API
        #        and should only be done with a major release.
        self.certs = dict()
        self.certs['cert_file'] = certfile
        self.certs['key_file'] = keyfile
        self.certs['ca_file'] = cafile
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
            'scanner_params':
                {k: v['name'] for k, v in self.scanner_params.items()}}

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
                    raise OSPDError('Invalid %s value' % key, 'start_scan')
            if param_type == 'boolean':
                if params[key] not in [0, 1]:
                    raise OSPDError('Invalid %s value' % key, 'start_scan')
            elif param_type == 'selection':
                selection = self.get_scanner_param_default(key).split('|')
                if params[key] not in selection:
                    raise OSPDError('Invalid %s value' % key, 'start_scan')
            if self.get_scanner_param_mandatory(key) and params[key] == '':
                    raise OSPDError('Mandatory %s value is missing' % key,
                                    'start_scan')
        return params

    def process_scan_params(self, params):
        """ This method is to be overridden by the child classes if necessary
        """
        return params

    def handle_start_scan_command(self, scan_et):
        """ Handles <start_scan> command.

        @return: Response string for <start_scan> command.
        """

        target_str = scan_et.attrib.get('target')
        if target_str is None:
            raise OSPDError('No target attribute', 'start_scan')
        ports_str = scan_et.attrib.get('ports')
        if ports_str is None:
            raise OSPDError('No ports attribute', 'start_scan')
        scan_id = scan_et.attrib.get('scan_id')
        if scan_id is not None and scan_id != '' and not valid_uuid(scan_id):
            raise OSPDError('Invalid scan_id UUID', 'start_scan')

        scanner_params = scan_et.find('scanner_params')
        if scanner_params is None:
            raise OSPDError('No scanner_params element', 'start_scan')

        params = self._preprocess_scan_params(scanner_params)

        # Dry run case.
        if 'dry_run' in params and int(params['dry_run']):
            scan_func = self.dry_run_scan
            scan_params = None
        else:
            scan_func = self.start_scan
            scan_params = self.process_scan_params(params)

        scan_id = self.create_scan(scan_id, target_str, ports_str, scan_params)
        scan_process = multiprocessing.Process(target=scan_func,
                                               args=(scan_id, target_str))
        self.scan_processes[scan_id] = scan_process
        scan_process.start()
        id_ = ET.Element('id')
        id_.text = scan_id
        return simple_response_str('start_scan', 200, 'OK', id_)

    def handle_stop_scan_command(self, scan_et):
        """ Handles <stop_scan> command.

        @return: Response string for <stop_scan> command.
        """

        scan_id = scan_et.attrib.get('scan_id')
        if scan_id is None or scan_id == '':
            raise OSPDError('No scan_id attribute', 'stop_scan')
        scan_process = self.scan_processes.get(scan_id)
        if not scan_process:
            raise OSPDError('Scan not found {0}.'.format(scan_id), 'stop_scan')
        if not scan_process.is_alive():
            raise OSPDError('Scan already stopped or finished.', 'stop_scan')

        logger.info('{0}: Scan stopping {1}.'.format(scan_id, scan_process.ident))
        scan_process.terminate()
        os.killpg(os.getpgid(scan_process.ident), 15)
        scan_process.join()
        self.set_scan_progress(scan_id, 100)
        self.add_scan_log(scan_id, name='', host='', value='Scan stopped.')
        logger.info('{0}: Scan stopped.'.format(scan_id))
        return simple_response_str('stop_scan', 200, 'OK')

    def exec_scan(self, scan_id, target):
        """ Asserts to False. Should be implemented by subclass. """
        raise NotImplementedError

    def finish_scan(self, scan_id):
        """ Sets a scan as finished. """
        self.set_scan_progress(scan_id, 100)
        logger.info("{0}: Scan finished.".format(scan_id))

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
        scanner_params = ET.Element('scanner_params')
        for param_id, param in self.scanner_params.items():
            param_xml = ET.SubElement(scanner_params, 'scanner_param')
            for name, value in [('id', param_id),
                                ('type', param['type'])]:
                param_xml.set(name, value)
            for name, value in [('name', param['name']),
                                ('description', param['description']),
                                ('default', param['default']),
                                ('mandatory', param['mandatory'])]:
                elem = ET.SubElement(param_xml, name)
                elem.text = str(value)
        return scanner_params

    def new_client_stream(self, sock):
        """ Returns a new ssl client stream from bind_socket. """

        assert sock
        newsocket, fromaddr = sock.accept()
        logger.debug("New connection from"
                     " {0}:{1}".format(fromaddr[0], fromaddr[1]))
        try:
            ssl_socket = ssl.wrap_socket(newsocket, cert_reqs=ssl.CERT_REQUIRED,
                                         server_side=True,
                                         certfile=self.certs['cert_file'],
                                         keyfile=self.certs['key_file'],
                                         ca_certs=self.certs['ca_file'],
                                         ssl_version=ssl.PROTOCOL_TLSv1)
        except (ssl.SSLError, socket.error) as message:
            logger.error(message)
            return None
        return ssl_socket

    def handle_client_stream(self, stream, is_unix=False):
        """ Handles stream of data received from client. """

        assert stream
        data = []
        stream.settimeout(2)
        while True:
            try:
                if is_unix:
                    data.append(stream.recv(1024))
                else:
                    data.append(stream.read(1024))
                if len(data) == 0:
                    logger.warning(
                        "Empty client stream (Connection unexpectedly closed)")
                    return
            except (AttributeError, ValueError) as message:
                logger.error(message)
                return
            except (ssl.SSLError) as exception:
                logger.debug('Error: {0}'.format(exception[0]))
                break
            except (socket.timeout) as exception:
                logger.debug('Error: {0}'.format(exception))
                break
        data = b''.join(data)
        if len(data) <= 0:
            logger.debug("Empty client stream")
            return
        try:
            response = self.handle_command(data)
        except OSPDError as exception:
            response = exception.as_xml()
            logger.debug('Command error: {0}'.format(exception.message))
        except Exception:
            logger.exception('While handling client command:')
            exception = OSPDError('Fatal error', 'error')
            response = exception.as_xml()
        if is_unix:
            stream.sendall(response)
        else:
            stream.write(response)

    def start_scan(self, scan_id, target_str):
        """ Starts the scan with scan_id. """

        os.setsid()
        logger.info("{0}: Scan started.".format(scan_id))
        target_list = target_str_to_list(target_str)
        if target_list is None:
            raise OSPDError('Erroneous targets list', 'start_scan')
        for index, target in enumerate(target_list):
            progress = float(index) * 100 / len(target_list)
            self.set_scan_progress(scan_id, int(progress))
            logger.info("{0}: Host scan started.".format(target))
            try:
                ret = self.exec_scan(scan_id, target)
                if ret == 0:
                    self.add_scan_host_detail(scan_id, name='host_status',
                                              host=target, value='0')
                elif ret == 1:
                    self.add_scan_host_detail(scan_id, name='host_status',
                                              host=target, value='1')
                elif ret == 2:
                    self.add_scan_host_detail(scan_id, name='host_status',
                                              host=target, value='2')
                else:
                    logger.debug('{0}: No host status returned'.format(target))
            except Exception as e:
                self.add_scan_error(scan_id, name='', host=target,
                                    value='Host process failure (%s).' % e)
                logger.exception('While scanning {0}:'.format(target))
            else:
                logger.info("{0}: Host scan finished.".format(target))

        self.finish_scan(scan_id)

    def dry_run_scan(self, scan_id, target_str):
        """ Dry runs a scan. """

        os.setsid()
        target_list = target_str_to_list(target_str)
        for _, target in enumerate(target_list):
            host = resolve_hostname(target)
            if host is None:
                logger.info("Couldn't resolve {0}.".format(target))
                continue
            logger.info("{0}: Dry run mode.".format(host))
            self.add_scan_log(scan_id, name='', host=host,
                              value='Dry run result')
        self.finish_scan(scan_id)

    def handle_timeout(self, scan_id, host):
        """ Handles scanner reaching timeout error. """
        self.add_scan_error(scan_id, host=host, name="Timeout",
                            value="{0} exec timeout."
                            .format(self.get_scanner_name()))

    def set_scan_progress(self, scan_id, progress):
        """ Sets scan_id scan's progress which is a number between 0 and 100. """
        self.scan_collection.set_progress(scan_id, progress)

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
        if details and details == '0':
            details = False
        else:
            details = True

        responses = []
        if scan_id and scan_id in self.scan_collection.ids_iterator():
            self.check_scan_process(scan_id)
            scan = self.get_scan_xml(scan_id, details)
            responses.append(scan)
        elif scan_id:
            text = "Failed to find scan '{0}'".format(scan_id)
            return simple_response_str('get_scans', 404, text)
        else:
            for scan_id in self.scan_collection.ids_iterator():
                self.check_scan_process(scan_id)
                scan = self.get_scan_xml(scan_id, details)
                responses.append(scan)
        return simple_response_str('get_scans', 200, 'OK', responses)

    def handle_help_command(self, scan_et):
        """ Handles <help> command.

        @return: Response string for <help> command.
        """
        help_format = scan_et.attrib.get('format')
        if help_format is None or help_format == "text":
            # Default help format is text.
            return simple_response_str('help', 200, 'OK',
                                       self.get_help_text())
        elif help_format == "xml":
            text = self.get_xml_str(self.commands)
            return simple_response_str('help', 200, 'OK', text)
        raise OSPDError('Bogus help format', 'help')

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
                command_txt = ''.join([command_txt, "\t Elements:\n",
                                       self.elements_as_text(info['elements'])])
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
            ele_txt = "\t{0}{1: <22} {2}".format(' ' * indent, elename,
                                                 desc_txt)
            text = ''.join([text, ele_txt])
        return text

    def handle_delete_scan_command(self, scan_et):
        """ Handles <delete_scan> command.

        @return: Response string for <delete_scan> command.
        """
        scan_id = scan_et.attrib.get('scan_id')
        if scan_id is None:
            return simple_response_str('delete_scan', 404,
                                       'No scan_id attribute')

        if not self.scan_exists(scan_id):
            text = "Failed to find scan '{0}'".format(scan_id)
            return simple_response_str('delete_scan', 404, text)
        self.check_scan_process(scan_id)
        if self.delete_scan(scan_id):
            return simple_response_str('delete_scan', 200, 'OK')
        raise OSPDError('Scan in progress', 'delete_scan')

    def delete_scan(self, scan_id):
        """ Deletes scan_id scan from collection.

        @return: 1 if scan deleted, 0 otherwise.
        """
        try:
            del self.scan_processes[scan_id]
        except KeyError:
            logger.debug('Scan process for {0} not found'.format(scan_id))
        return self.scan_collection.delete_scan(scan_id)

    def get_scan_results_xml(self, scan_id):
        """ Gets scan_id scan's results in XML format.

        @return: String of scan results in xml.
        """
        results = ET.Element('results')
        for result in self.scan_collection.results_iterator(scan_id):
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
            elem = ET.Element(tag)
            if isinstance(value, dict):
                for value in self.get_xml_str(value):
                    elem.append(value)
            elif isinstance(value, list):
                value = ', '.join([m for m in value])
                elem.text = value
            else:
                elem.text = value
            responses.append(elem)
        return responses

    def get_scan_xml(self, scan_id, detailed=True):
        """ Gets scan in XML format.

        @return: String of scan in xml format.
        """
        if not scan_id:
            return ET.Element('scan')

        target = self.get_scan_target(scan_id)
        progress = self.get_scan_progress(scan_id)
        start_time = self.get_scan_start_time(scan_id)
        end_time = self.get_scan_end_time(scan_id)
        response = ET.Element('scan')
        for name, value in [('id', scan_id),
                            ('target', target),
                            ('progress', progress),
                            ('start_time', start_time),
                            ('end_time', end_time)]:
            response.set(name, str(value))
        if detailed:
            response.append(self.get_scan_results_xml(scan_id))
        return response

    def handle_get_scanner_details(self):
        """ Handles <get_scanner_details> command.

        @return: Response string for <get_scanner_details> command.
        """
        desc_xml = ET.Element('description')
        desc_xml.text = self.get_scanner_description()
        details = [
            desc_xml,
            self.get_scanner_params_xml()
        ]
        return simple_response_str('get_scanner_details', 200, 'OK', details)

    def handle_get_version_command(self):
        """ Handles <get_version> command.

        @return: Response string for <get_version> command.
        """
        protocol = ET.Element('protocol')
        for name, value in [('name', 'OSP'), ('version', self.get_protocol_version())]:
            elem = ET.SubElement(protocol, name)
            elem.text = value

        daemon = ET.Element('daemon')
        for name, value in [('name', self.get_daemon_name()), ('version', self.get_daemon_version())]:
            elem = ET.SubElement(daemon, name)
            elem.text = value

        scanner = ET.Element('scanner')
        for name, value in [('name', self.get_scanner_name()), ('version', self.get_scanner_version())]:
            elem = ET.SubElement(scanner, name)
            elem.text = value

        return simple_response_str('get_version', 200, 'OK', [protocol, daemon, scanner])

    def handle_command(self, command):
        """ Handles an osp command in a string.

        @return: OSP Response to command.
        """
        try:
            tree = ET.fromstring(command)
        except ET.ParseError:
            logger.debug("Erroneous client input: {0}".format(command))
            raise OSPDError('Invalid data')

        if not self.command_exists(tree.tag) and tree.tag != "authenticate":
            raise OSPDError('Bogus command name')

        if tree.tag == "get_version":
            return self.handle_get_version_command()
        elif tree.tag == "start_scan":
            return self.handle_start_scan_command(tree)
        elif tree.tag == "stop_scan":
            return self.handle_stop_scan_command(tree)
        elif tree.tag == "get_scans":
            return self.handle_get_scans_command(tree)
        elif tree.tag == "delete_scan":
            return self.handle_delete_scan_command(tree)
        elif tree.tag == "help":
            return self.handle_help_command(tree)
        elif tree.tag == "get_scanner_details":
            return self.handle_get_scanner_details()
        else:
            assert False, "Unhandled command: {0}".format(tree.tag)

    def check(self):
        """ Asserts to False. Should be implemented by subclass. """
        raise NotImplementedError

    def run(self, address, port, unix_path):
        """ Starts the Daemon, handling commands until interrupted.

        @return False if error. Runs indefinitely otherwise.
        """
        assert address or unix_path
        if unix_path:
            sock = bind_unix_socket(unix_path)
        else:
            sock = bind_socket(address, port)
        if sock is None:
            return False

        try:
            while True:
                if unix_path:
                    client_stream, _ = sock.accept()
                    logger.debug("New connection from {0}".format(unix_path))
                    self.handle_client_stream(client_stream, True)
                else:
                    client_stream = self.new_client_stream(sock)
                    if client_stream is None:
                        continue
                    self.handle_client_stream(client_stream, False)
                close_client_stream(client_stream, unix_path)
        except KeyboardInterrupt:
            logger.info("Received Ctrl-C shutting-down ...")
        finally:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    def create_scan(self, scan_id, target, ports, options):
        """ Creates a new scan.

        @target: Target to scan.
        @options: Miscellaneous scan options.

        @return: New scan's ID.
        """
        return self.scan_collection.create_scan(scan_id, target, ports, options)

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
            self.set_scan_progress(scan_id, 100)
            self.add_scan_error(scan_id, name="", host="",
                                value="Scan process failure.")
            logger.info("{0}: Scan terminated.".format(scan_id))
        elif progress == 100:
            scan_process.join()

    def get_scan_progress(self, scan_id):
        """ Gives a scan's current progress value. """
        return self.scan_collection.get_progress(scan_id)

    def get_scan_target(self, scan_id):
        """ Gives a scan's target. """
        return self.scan_collection.get_target(scan_id)

    def get_scan_ports(self, scan_id):
        """ Gives a scan's ports list. """
        return self.scan_collection.get_ports(scan_id)

    def get_scan_start_time(self, scan_id):
        """ Gives a scan's start time. """
        return self.scan_collection.get_start_time(scan_id)

    def get_scan_end_time(self, scan_id):
        """ Gives a scan's end time. """
        return self.scan_collection.get_end_time(scan_id)

    def add_scan_log(self, scan_id, host='', name='', value='', port='',
                     test_id='', qod=''):
        """ Adds a log result to scan_id scan. """
        self.scan_collection.add_result(scan_id, ResultType.LOG, host, name,
                                        value, port, test_id, 0.0, qod)

    def add_scan_error(self, scan_id, host='', name='', value='', port=''):
        """ Adds an error result to scan_id scan. """
        self.scan_collection.add_result(scan_id, ResultType.ERROR, host, name,
                                        value, port)

    def add_scan_host_detail(self, scan_id, host='', name='', value=''):
        """ Adds a host detail result to scan_id scan. """
        self.scan_collection.add_result(scan_id, ResultType.HOST_DETAIL, host,
                                        name, value)

    def add_scan_alarm(self, scan_id, host='', name='', value='', port='',
                       test_id='', severity='', qod=''):
        """ Adds an alarm result to scan_id scan. """
        self.scan_collection.add_result(scan_id, ResultType.ALARM, host, name,
                                        value, port, test_id, severity, qod)
