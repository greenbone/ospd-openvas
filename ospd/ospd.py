# $Id$
# Description:
# OSP Daemon core class.
#
# Authors:
# Hani Benhabiles <hani.benhabiles@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
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

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
import socket
import ssl
import thread
from misc import ScanCollection, OSPLogger, ResultType

OSP_VERSION = "0.0.1"

class OSPDaemon(object):
    """ Daemon class for OSP traffic handling.

    Every scanner wrapper should subclass it and make necessary additions and
    changes.
    * Add any needed parameters in __init__.
    * Implement check() method which verifies scanner availability and other
      environment related conditions.
    * Implement handle_start_scan_command and exec_scan methods which are
      specific to handling the <start_scan> command, executing the wrapped
      scanner and storing the results.
    * Implement other methods that assert to False such as get_scanner_name,
      get_scanner_version.
    * Use Call set_command_attributes at init time to add scanner command
      specific options eg. the w3af profile for w3af wrapper.

    See OSPDw3af and OSPDOvaldi for wrappers examples.
    """

    def __init__(self, certfile, keyfile, cafile, timeout, debug, port,
                 address):
        """ Initializes the daemon's internal data. """
        # Generate certificate for default params with openvas-mkcert
        self.cert_file = certfile
        self.key_file = keyfile
        self.ca_file = cafile
        self.port = port
        self.timeout = timeout
        self.scan_collection = ScanCollection()
        self.logger = OSPLogger(debug)
        self.address = address
        self.name = "generic ospd"
        self.version = "generic version"
        self.description = "No description"
        self.scanner_params = dict()
        self.commands = self.get_commands_table()
        self.socket = None

    def get_commands_table(self):
        """ Initializes the supported commands and their info. """

        return {'start_scan' : {'description' : 'Start a new scan.',
                                'attributes' : {'target' :
                                                'Target host to scan'},
                                'elements' : None},
                'help' : {'description' : 'Print the commands help.',
                          'attributes' : None,
                          'elements' : None},
                'get_scans' : {'description' : 'List the scans in buffer.',
                               'attributes' :
                               {'scan_id' : 'ID of a specific scan to get.',
                                'details' : 'Whether to return the full'\
                                            ' scan report.'},
                               'elements' : None},
                'delete_scan' : {'description' : 'Delete a finished scan.',
                                 'attributes' :
                                 {'scan_id' : 'ID of scan to delete.'},
                                 'elements' : None},
                'get_version' : {'description' : 'Return various versions.',
                                 'attributes' : None,
                                 'elements' : None},
                'get_scanner_details' : {'description' :
                                         'Return scanner description and'\
                                         ' parameters',
                                         'attributes' : None,
                                         'elements' : None}}

    def set_command_attributes(self, name, attributes):
        """ Sets the xml attributes of a specified command. """
        if self.command_exists(name):
            command = self.commands.get(name)
            command['attributes'] = attributes

    def set_command_elements(self, name, elements):
        """ Sets the xml subelements of a specified command. """
        if self.command_exists(name):
            command = self.commands.get(name)
            command['elements'] = elements

    def command_exists(self, name):
        """ Checks if a commands exists. """
        return name in self.commands.keys()

    def get_scanner_name(self):
        """ Asserts to False. Should be implemented by subclass. """
        assert False, 'get_scanner_name() not implemented.'

    def get_scanner_version(self):
        """ Asserts to False. Should be implemented by subclass. """
        assert False, 'get_scanner_version() not implemented.'

    def handle_start_scan_command(self, scan_et):
        """ Asserts to False. Should be implemented by subclass. """
        assert False, 'handle_start_scan_command() not implemented.'

    def exec_scan(self, scan_id):
        """ Asserts to False. Should be implemented by subclass. """
        assert False, 'exec_scan() not implemented.'

    def finish_scan(self, scan_id):
        """ Sets a scan as finished. """
        self.set_scan_progress(scan_id, 100)
        self.logger.debug(2, "{0}: Scan finished.".format(scan_id))

    def get_daemon_name(self):
        """ Gives osp daemon's name. """
        return self.name

    def get_daemon_version(self):
        """ Gives osp daemon's version. """
        return self.version

    def get_scanner_description(self):
        """ Returns the OSP Daemon's description. """
        return self.description

    def get_scanner_params_xml(self):
        """ Returns the OSP Daemon's scanner params in xml format. """
        params_str = ""
        for param_id, param in self.scanner_params.items():
            param_str = "<scanner_param id='{0}' type='{1}'>"\
                        "<name>{2}</name><description>{3}</description>"\
                        "</scanner_param>".format(param_id, param['type'],
                                                  param['name'],
                                                  param['description'])
            params_str = ''.join([params_str, param_str])
        return "<scanner_params>{0}</scanner_params>".format(params_str)

    def bind_socket(self):
        """ Returns a socket bound on (address:port). """
        bindsocket = socket.socket()
        try:
            bindsocket.bind((self.address, self.port))
        except socket.error:
            self.logger.error("Couldn't bind socket on {0}:{1}"\
                               .format(self.address, self.port))
            return None

        bindsocket.listen(0)
        return bindsocket

    def new_client_stream(self):
        """ Returns a new ssl client stream from bind_socket. """

        newsocket, fromaddr = self.socket.accept()
        self.logger.debug(1, "New connection from"
                             " {0}:{1}".format(fromaddr[0], fromaddr[1]))
        try:
            ssl_socket = ssl.wrap_socket(newsocket, cert_reqs=ssl.CERT_REQUIRED,
                                         server_side=True,
                                         certfile=self.cert_file,
                                         keyfile=self.key_file,
                                         ca_certs=self.ca_file,
                                         ssl_version=ssl.PROTOCOL_TLSv1)
        except ssl.SSLError as err:
            self.logger.error(err)
            return None
        return ssl_socket

    def handle_client_stream(self, stream):
        """ Handles stream of data received from client. """
        if stream is None:
            return
        data = ''
        stream.settimeout(2)
        while True:
            try:
                data = ''.join([data, stream.read(1024)])
                if len(data) == 0:
                    self.logger.debug(1, "Empty client stream")
                    return
            except AttributeError:
                self.logger.debug(1, "Couldn't read client input.")
                return
            except ssl.SSLError:
                break
        if len(data) <= 0:
            self.logger.debug(1, "Empty client stream")
            return
        response = self.handle_command(data)
        stream.write(response)

    def close_client_stream(self, client_stream):
        """ Closes provided client stream """
        try:
            client_stream.shutdown(socket.SHUT_RDWR)
        except socket.error, msg:
            self.logger.debug(1, msg)
        client_stream.close()

    def start_daemon(self):
        """ Initialize the OSP daemon.

        @return True if success, False if error.
        """
        self.socket = self.bind_socket()
        if self.socket is None:
            return False
        return True

    def start_scan(self, scan_id):
        """ Starts the scan with scan_id. """

        self.logger.debug(2, "{0}: Scan started.".format(scan_id))
        thread.start_new_thread(self.exec_scan, (scan_id, ))

    def handle_timeout(self, scan_id):
        """ Handles scanner reaching timeout error. """
        self.add_scan_error(scan_id, name="Timeout",
                            value="{0} exec timeout."\
                                   .format(self.get_scanner_name()))
        self.finish_scan(scan_id)

    def set_scan_progress(self, scan_id, progress):
        """ Sets scan_id scan's progress. """
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

        details = True
        scan_id = scan_et.attrib.get('scan_id')
        details = scan_et.attrib.get('details')
        if details and details == '0':
            details = False

        response = ""
        if scan_id and scan_id in self.scan_collection.ids_iterator():
            scan_str = self.get_scan_xml(scan_id, details)
            response = ''.join([response, scan_str])
        elif scan_id:
            text = "Failed to find scan '{0}'".format(scan_id)
            return self.simple_response_str('get_scans', 404, text)
        else:
            for scan_id in self.scan_collection.ids_iterator():
                scan_str = self.get_scan_xml(scan_id, details)
                response = ''.join([response, scan_str])
        return self.simple_response_str('get_scans', 200, 'OK', response)

    def handle_help_command(self, scan_et):
        """ Handles <help> command.

        @return: Response string for <help> command.
        """
        help_format = scan_et.attrib.get('format')
        if help_format is None:
            # Default help format is text.
            return self.simple_response_str('help', 200, 'OK',
                                            self.get_help_text())
        elif help_format == "xml":
            text = self.get_xml_str(self.commands)
            return self.simple_response_str('help', 200, 'OK', text)
        else:
            return self.simple_response_str('help', 400, 'Bogus help format')

    def get_help_text(self):
        """ Returns the help output in plain text format."""

        txt = str('\n')
        for name, info in self.commands.iteritems():
            command_txt = "\t{0: <22} {1}\n".format(name, info['description'])
            if info['attributes']:
                command_txt = ''.join([command_txt, "\t Attributes:\n"])
                for attrname, attrdesc in info['attributes'].iteritems():
                    attr_txt = "\t  {0: <22} {1}\n".format(attrname, attrdesc)
                    command_txt = ''.join([command_txt, attr_txt])
            if info['elements']:
                command_txt = ''.join([command_txt, "\t Elements:\n",
                                       self.elements_as_text(info['elements'])])
            txt = ''.join([txt, command_txt])
        return txt

    def elements_as_text(self, elems, indent=2):
        """ Returns the elems dictionnary as formatted plain text. """
        assert elems
        text = ""
        for elename, eledesc in elems.iteritems():
            if type(eledesc) == type(dict()):
                desc_txt = self.elements_as_text(eledesc, indent + 2)
                desc_txt = ''.join(['\n', desc_txt])
            elif type(eledesc) == type(str()):
                desc_txt = ''.join([eledesc, '\n'])
            else:
                assert False, "Only string or dictionnary"
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
            return self.simple_response_str('delete_scan', 404,
                                            'No scan_id attribute')

        if not self.scan_exists(scan_id):
            text = "Failed to find scan '{0}'".format(scan_id)
            return self.simple_response_str('delete_scan', 404, text)
        if self.delete_scan(scan_id):
            return self.simple_response_str('delete_scan', 200, 'OK')
        else:
            return self.simple_response_str('delete_scan', 400,
                                            'Scan in progress')

    def delete_scan(self, scan_id):
        """ Deletes scan_id scan from collection.

        @return: 1 if scan deleted, 0 otherwise.
        """
        return self.scan_collection.delete_scan(scan_id)

    def get_scan_results_xml(self, scan_id):
        """ Gets scan_id scan's results in XML format.

        @return: String of scan results in xml.
        """
        results_str = str()
        for result in self.scan_collection.results_iterator(scan_id):
            result_str = self.get_result_xml(result)
            results_str = ''.join([results_str, result_str])
        return ''.join(['<results>', results_str, '</results>'])

    def get_result_xml(self, result):
        """ Formats a scan result to XML format. """

        result_type = ResultType.get_str(result[0])
        return '<result name="{0}" type="{1}">{2}</result>'\
                .format(result[1], result_type, result[2])

    def get_xml_str(self, data):
        """ Creates a string in XML Format using the provided data structure.

        @param: Dictionnary of xml tags and their elements.

        @return: String of data in xml format.
        """

        response = str()
        for tag, value in data.items():
            if type(value) == type(dict()):
                value = self.get_xml_str(value)
            elif type(value) == type(list()):
                value = ', '.join([m for m in value])
            elif value is None:
                value = str()
            response = ''.join([response,
                                "<{0}>{1}</{2}>".format(tag, value,
                                                        tag.split()[0])])
        return response

    def simple_response_str(self, command, status, status_text, content=""):
        """ Creates an OSP response XML string.

        @param: OSP Command to respond to.
        @param: Status of the response.
        @param: Status text of the response.
        @param: Text part of the response XML element.

        @return: String of response in xml format.
        """
        assert command
        assert status
        assert status_text
        return '<{0}_response status="{1}" status_text="{2}">{3}'\
               '</{0}_response>'.format(command, status, status_text, content)


    def get_scan_xml(self, scan_id, detailed=True):
        """ Gets scan in XML format.

        @return: String of scan in xml format.
        """
        if not scan_id:
            return self.get_xml_str({'scan': ''})

        target = self.get_scan_target(scan_id)
        progress = self.get_scan_progress(scan_id)
        start_time = self.get_scan_start_time(scan_id)
        end_time = self.get_scan_end_time(scan_id)
        if detailed is False:
            results_str = ""
        else:
            results_str = self.get_scan_results_xml(scan_id)

        return '<scan id="{0}" target="{1}" progress="{2}"'\
               ' start_time="{3}" end_time="{4}">{5}</scan>'\
                .format(scan_id, target, progress, start_time, end_time,
                        results_str)

    def handle_get_scanner_details(self):
        """ Handles <get_scanner_details> command.

        @return: Response string for <get_version> command.
        """
        description = self.get_scanner_description()
        scanner_params = self.get_scanner_params_xml()
        details = "<description>{0}</description>{1}".format(description,
                                                             scanner_params)
        return self.simple_response_str('get_scanner_details', 200, 'OK',
                                        details)
    def handle_get_version_command(self):
        """ Handles <get_version> command.

        @return: Response string for <get_version> command.
        """
        protocol = self.get_xml_str({'protocol' : {'name' : 'OSP',
                                                   'version' : OSP_VERSION}})

        daemon_name = self.get_daemon_name()
        daemon_ver = self.get_daemon_version()
        daemon = self.get_xml_str({'daemon' : {'name' : daemon_name,
                                               'version' : daemon_ver}})

        scanner_name = self.get_scanner_name()
        scanner_ver = self.get_scanner_version()
        scanner = self.get_xml_str({'scanner' : {'name' : scanner_name,
                                                 'version' : scanner_ver}})

        text = ''.join([protocol, daemon, scanner])
        return self.simple_response_str('get_version', 200, 'OK', text)

    def handle_command(self, command):
        """ Handles an osp command in a string.

        @return: OSP Response to command.
        """
        try:
            tree = ET.fromstring(command)
        except ET.ParseError:
            self.logger.debug(1, "Erroneous client input: {0}".format(command))
            return self.simple_response_str('osp', 400, 'Invalid data')

        if not self.command_exists(tree.tag) and tree.tag != "authenticate":
            return self.simple_response_str('osp', 400, 'Bogus command name')

        if tree.tag == "get_version":
            return self.handle_get_version_command()
        elif tree.tag == "start_scan":
            return self.handle_start_scan_command(tree)
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
        assert False, 'check() not implemented.'

    def run(self):
        """ Starts the Daemon, handling commands until interrupted.

        @return False if error. Runs indefinitely otherwise.
        """
        if not self.start_daemon():
            return False

        while True:
            client_stream = self.new_client_stream()
            if client_stream is None:
                continue
            self.handle_client_stream(client_stream)
            self.close_client_stream(client_stream)

    def create_scan(self, target, options):
        """ Creates a new scan.

        @target: Target to scan.
        @options: Miscellaneous scan options.

        @return: New scan's ID.
        """
        return self.scan_collection.create_scan(target, options)

    def get_scan_options(self, scan_id):
        """ Gives a scan's list of options. """
        return self.scan_collection.get_options(scan_id)

    def set_scan_option(self, scan_id, name, value):
        """ Sets a scan's option to a provided value. """
        return self.scan_collection.set_option(scan_id, name, value)

    def get_scan_progress(self, scan_id):
        """ Gives a scan's current progress value. """
        return self.scan_collection.get_progress(scan_id)

    def get_scan_target(self, scan_id):
        """ Gives a scan's target. """
        return self.scan_collection.get_target(scan_id)

    def get_scan_start_time(self, scan_id):
        """ Gives a scan's start time. """
        return self.scan_collection.get_start_time(scan_id)

    def get_scan_end_time(self, scan_id):
        """ Gives a scan's end time. """
        return self.scan_collection.get_end_time(scan_id)

    def add_scan_log(self, scan_id, name="", value=""):
        """ Adds a log result to scan_id scan. """
        self.scan_collection.add_log(scan_id, name, value)

    def add_scan_error(self, scan_id, name="", value=""):
        """ Adds an error result to scan_id scan. """
        self.scan_collection.add_error(scan_id, name, value)

    def add_scan_alarm(self, scan_id, name="", value=""):
        """ Adds an alarm result to scan_id scan. """
        self.scan_collection.add_alarm(scan_id, name, value)
