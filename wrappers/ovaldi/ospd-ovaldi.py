#!/usr/bin/env python

# $Id$
# Description:
# ovaldi wrapper for OSPD.
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

import shutil
import os
import inspect
import base64
import socket
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

# Set OSPD Directory in syspaths, for imports
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
ospdir = os.path.dirname(os.path.dirname(currentdir))
os.sys.path.insert(0, ospdir)
# Local imports
from ospd.ospd import OSPDaemon
from ospd.misc import create_args_parser, get_common_args

# External modules.
try:
    import paramiko
except:
    print "paramiko not found."
    print "# pip install paramiko (Or apt-get install python-paramiko.)"
    exit(1)

ospd_ovaldi_description = """
This scanner runs the Open Source OVAL scanner 'ovaldi' being installed on the
target systems. To do so, a SSH access is required. Note that the current
version does not support Windows or other systems without SSH access.

The OVAL Interpreter is a freely available reference implementation that
demonstrates the evaluation of OVAL Definitions. Based on a set of Definitions
the Interpreter collects system information, evaluates it, and generates a
detailed OVAL Results file. It has been developed to demonstrate the usability
of OVAL Definitions and to ensure correct syntax and adherence to the OVAL
Schemas by definition writers.

IMPORTANT: Please note that the OVAL Interpreter is not an enterprise scanning
tool; it is a simplistic, command-line interface that has the ability to execute
OVAL Content on an end system.

For more see the homepage of ovaldi at MITRE:
    https://oval.mitre.org/language/interpreter.html
"""

ospd_ovaldi_params = [
    { 'id' : 'username',
      'type' : 'string',
      'name' : 'SSH Username',
      'description' : 'The SSH username used to log into the target and to run'
                      ' the ovaldi tool installed on that target.',
    },
    { 'id' : 'password',
      'type' : 'password',
      'name' : 'SSH Password',
      'description' :
       'The SSH password for the given username which is used to log into the '
       'target and to run the ovaldi tool installed on that target. This should'
       ' not be a privileged user like "root", a regular privileged user '
       'account should be sufficient in most cases.'
    },
    { 'id' : 'port',
      'type' : 'int',
      'name' : 'SSH Port',
      'description' :
       'The SSH port which to use for logging in with the given'
       ' username/password. the ovaldi tool installed on that target.',
    },
    { 'id' : 'definitions_file',
      'type' : 'base64',
      'name' : 'Oval Definitions',
      'description' : 'OVAL definitions is a XML object containing many single'
                      ' oval definition objects including also any required '
                      'oval test and other objects.',
    },
]

# ospd-ovaldi daemon class.
class OSPDOvaldi(OSPDaemon):
    """ Class for ospd-ovaldi daemon. """

    def __init__(self, certfile, keyfile, cafile, timeout, debug, port,
                 address):
        """ Initializes the ospd-ovaldi daemon's internal data. """
        super(OSPDOvaldi, self).__init__(certfile=certfile, keyfile=keyfile,
                                         cafile=cafile, timeout=timeout,
                                         debug=debug, port=port,
                                         address=address)

        self.version = "0.0.1"
        self.description = ospd_ovaldi_description
        self.scanner_params = ospd_ovaldi_params
        self.schema_dir = "/usr/share/ovaldi/xml"
        self.set_command_elements\
              ("start_scan",
               { 'username' : 'SSH Username.',
                 'password' : 'SSH Password.',
                 'definitions_file' : 'Definitions file content in base64',
                 'port' : 'SSH Port.'})

    def check(self):
        return True

    def get_scanner_name(self):
        """ Gives the used scanner's name. """
        return "ovaldi"

    def get_scanner_version(self):
        """ Gives the used scanner's version. """
        return self.version # XXX: ovaldi is different on each target.

    def handle_start_scan_command(self, scan_et):
        """ Handles the OSP <start_scan> command element tree. """
        # Validate scan information
        target = scan_et.attrib.get('target')
        if target is None:
            return self.simple_response_str('start_scan', 400,
                                            'No target attribute')
        scanner_params = scan_et.find('scanner_params')
        if scanner_params is None:
            return self.simple_response_str('start_scan', 400,
                                            'No scanner_params element')

        username = scanner_params.find('username')
        if username is None or username.text is None:
            return self.simple_response_str('start_scan', 400,
                                            'No username element')
        password = scanner_params.find('password')
        if password is None or password.text is None:
            return self.simple_response_str('start_scan', 400,
                                            'No password element')
        definitions = scanner_params.find('definitions_file')
        if definitions is None or definitions.text is None:
            return self.simple_response_str('start_scan', 400,
                                            'No definitions_file element')

        username = username.text
        password = password.text

        # Default port: 22.
        port = scanner_params.find('port')
        if port is None:
            port = 22
        else:
            try:
                port = int(port.text)
            except ValueError:
                return self.simple_response_str('start_scan', 400,
                                                'Invalid port value')

        options = dict()
        options['username'] = username
        options['password'] = password
        options['port'] = port
        try:
            options['definitions'] = base64.b64decode(definitions.text)
        except TypeError:
            err = "Couldn't decode base64 definitions file"
            return self.simple_response_str('start_scan', 400, err)

        # Create new Scan
        scan_id = self.create_scan(target, options)

        # Start Scan
        self.start_scan(scan_id)
        text = '<id>{0}</id>'.format(scan_id)
        return self.simple_response_str('start_scan', 200, 'OK', text)

    def finish_scan_with_err(self, scan_id, local_dir=None,
                             err="Unknown error"):
        """
        Add an error message to a scan and finish it. Cleanup the results
        dir if provided.
        """
        if local_dir:
            shutil.rmtree(local_dir)
        self.logger.debug(2, err)
        self.add_scan_error(scan_id, value=err)
        self.finish_scan(scan_id)

    def check_ovaldi(self, ssh, sftp):
        """
        Check that ovaldi and the required files are installed correctly on the
        target.

        return None if success, error string otherwise.
        """
        chan = ssh.get_transport().open_session()
        chan.exec_command("which ovaldi")
        status = chan.recv_exit_status()
        chan.close()
        if status != 0:
            return "ovaldi not found on target host."

        # Is oval schema directory present ?
        try:
            sftp.stat(self.schema_dir)
        except IOError, err:
            return "oval schema folder {0} not found.".format(self.schema_dir)
        return None

    def exec_scan(self, scan_id):
        """ Starts the ovaldi scanner for scan_id scan. """
        options = self.get_scan_options(scan_id)
        target = self.get_scan_target(scan_id)
        username = options['username']
        password = options['password']
        definitions = options['definitions']
        port = options['port']
        local_dir = '/tmp/ovaldi-results-{0}'.format(scan_id)
        os.mkdir(local_dir)
        defs_file = '{0}/ovaldi-defs.xml'.format(local_dir)

        # Write definitions to temporary file
        with open(defs_file, 'w') as f:
            f.write(definitions)

        # Connect to target
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(hostname=target, username=username, password=password,
                        timeout=self.timeout)
        except (paramiko.ssh_exception.AuthenticationException,
                socket.error), err:
            # Errors: No route to host, connection timeout, authentication
            # failure etc,.
            return self.finish_scan_with_err(scan_id, local_dir, err)

        # Can we SFTP to the target ?
        try:
            sftp = ssh.open_sftp()
        except paramiko.ssh_exception.SSHException:
            err = "Couldn't SFTP to the target host."
            ssh.close()
            return self.finish_scan_with_err(scan_id, None, err)

        # Check for ovaldi on the target.
        err = self.check_ovaldi(ssh, sftp)
        if err:
            sftp.close()
            ssh.close()
            return self.finish_scan_with_err(scan_id, local_dir, err)

        # Create temp dir and copy definitions file.
        target_dir = "/tmp/{0}".format(scan_id)
        try:
            sftp.mkdir(target_dir)
        except IOError, err:
            err = "Failed to mkdir {0} on target: {1}".format(target_dir, err)
            sftp.close()
            ssh.close()
            return self.finish_scan_with_err(scan_id, None, err)
        target_defs_path = "{0}/definitions.xml".format(target_dir)
        sftp.put(defs_file, target_defs_path)

        # Run ovaldi
        results_path = "{0}/results.xml".format(target_dir)
        syschar_path = "{0}/oval_syschar.xml".format(target_dir)
        log_path = "{0}/ovaldi.log".format(target_dir)
        command = "ovaldi -m -s -r {0} -d {1} -o {2} -y {3} -a {4}"\
                   .format(results_path, syschar_path, target_defs_path,
                           target_dir, self.schema_dir)
        self.logger.debug(2, "Running command: {0}".format(command))
        stdin, stdout, stderr = ssh.exec_command(command)
        # Flush stdout buffer, to continue execution.
        stdout.readlines()
        # Copy results from target
        # One case where *.xml files are missing: Definitions file doesn't
        # match ovaldi version or its schema is not valid, thus only
        # ovaldi.log was generated and no further scan occured.
        # XXX: Extract/Reorganize files content into multiple results.
        # results.xml
        try:
            local_results = "{0}/results.xml".format(local_dir)
            sftp.get(results_path, local_results)
            self.parse_results_xml(local_results, scan_id)
        except IOError, err:
            msg = "Couldn't get results.xml: {0}".format(err)
            self.logger.debug(2, msg)
            self.add_scan_error(scan_id, value=msg)
        # oval_syschar.xml
        try:
            local_syschar = "{0}/oval_syschar.xml".format(local_dir)
            sftp.get(syschar_path, local_syschar)
            self.parse_oval_syschar_xml(local_syschar, scan_id)
        except IOError, err:
            msg = "Couldn't get oval_syschar.xml: {0}".format(err)
            self.logger.debug(2, msg)
            self.add_scan_error(scan_id, value=msg)
        # ovaldi.log
        try:
            local_log = "{0}/ovaldi.log".format(local_dir)
            sftp.get(log_path, local_log)
            self.parse_ovaldi_log(local_log, scan_id)
        except IOError, err:
            msg = "Couldn't get ovaldi.log: {0}".format(err)
            self.logger.debug(2, msg)
            self.add_scan_error(scan_id, value=msg)
        # Cleanup temporary directories and close connection.
        sftp.close()
        if self.logger.get_level() < 1:
            ssh.exec_command("rm -rf {0}".format(target_dir))
        else:
            self.logger.debug(2, "{0} not removed.".format(target_dir))

        ssh.close()
        shutil.rmtree(local_dir)
        self.finish_scan(scan_id)

    def parse_oval_syschar_xml(self, file_path, scan_id):
        """ Parses the content of oval_syschar.xml file to scan results """

        try:
            with open(file_path, 'r') as f:
                file_content = f.read()

            # Extract /oval_system_characteristcs/system_info
            system_info = None
            tree = ET.fromstring(file_content)
            for child in tree:
                if child.tag.endswith('system_info'):
                    system_info = child
                elif child.tag.endswith('generator'):
                    generator = child
            for child in generator:
                value = child.tag
                if '}' in child.tag:
                    value = child.tag.split('}')[1]
                name = 'syschar_generator:{0}'.format(value)
                self.add_scan_log(scan_id, name=name, value=child.text)

            for child in system_info:
                if not child.tag.endswith('interfaces'):
                    name = 'system_info:{0}'.format(child.tag.split('}')[1])
                    self.add_scan_log(scan_id, name=name, value=child.text)
                else:
                    # Extract interfaces info from <sytem_info><interfaces>...
                    self.parse_system_info_interfaces(child, scan_id)

            # XXX: Extract /oval_system_characteristcs/system_data/uname_item*
        except IOError:
            self.logger.debug(1, "{0}: Couldn't open file.".format(file_path))

    def parse_system_info_interfaces(self, interfaces, scan_id):
        """ Parses interfaces information in ovaldi's system_info's interfaces
        and insert it in scan results. """

        for interface in interfaces:
            name = str()
            address = str()
            mac = str()
            for child in interface:
                if child.tag.endswith('interface_name'):
                    name = child.text
                elif child.tag.endswith('ip_address'):
                    address = child.text
                elif child.tag.endswith('mac_address'):
                    mac = child.text
            result_str = '{0}|{1}|{2}'.format(name, address, mac)
            self.add_scan_log(scan_id, 'system_info:interface',
                              result_str)

    def parse_results_xml(self, file_path, scan_id):
        """ Parses results file into scan results. """

        try:
            with open(file_path, 'r') as f:
                file_content = f.read()
            # Extract oval definitions results and other relevant information.
            tree = ET.fromstring(file_content)
            for child in tree:
                if child.tag.endswith('generator'):
                    generator = child
                elif child.tag.endswith('oval_definitions'):
                    oval_defs = child
                elif child.tag.endswith('results'):
                    results = child
            for child in generator:
                value = child.tag
                if '}' in child.tag:
                    value = child.tag.split('}')[1]
                name = 'results_generator:{0}'.format(value)
                self.add_scan_log(scan_id, name=name, value=child.text)
            self.parse_oval_results(oval_defs, results, scan_id)
        except IOError:
            self.logger.debug(1, "{0}: Couldn't open file.".format(file_path))

    def parse_oval_results(self, oval_defs, results, scan_id):
        """ Parses oval_definitions and results elements from results file. """

        for child in oval_defs:
            if child.tag.endswith('generator'):
                generator = child
            elif child.tag.endswith('definitions'):
                definitions = child
        for child in generator:
            name = 'defs_generator:{0}'.format(child.tag.split('}')[1])
            self.add_scan_log(scan_id, name=name, value=child.text)
        for definition in definitions:
            def_class = definition.attrib.get('class')
            def_id = definition.attrib.get('id')
            def_result = self.get_definition_result(def_id, results)
            if def_result == 'true':
                # Skip: false, error, unknown, not applicable.
                self.add_scan_alarm(scan_id, name=def_id, value="")

    def get_definition_result(self, def_id, results):
        """ Gets an oval definition's result value in results element from
        results xml file. """
        for child in results:
            if child.tag.endswith('system'):
                system = child
                break
        for child in system:
            if child.tag.endswith('definitions'):
                definitions = child
                break
        for child in definitions:
            if child.attrib.get('definition_id') == def_id:
                return child.attrib.get('result')
        return "Not found"

    def parse_ovaldi_log(self, file_path, scan_id):
        """ Parses the content of ovaldi.log file to scan results """

        try:
            with open(file_path, 'r') as f:
                file_content = f.read()
            self.add_scan_log(scan_id, name="ovaldi.log", value=file_content)
        except IOError:
            self.logger.debug(1, "{0}: Couldn't open file.".format(file_path))

# Main starts here
if __name__ == '__main__':
    # Common args parser.
    parser = create_args_parser("OSPD - Remote Ovaldi wrapper")

    # Common args
    cargs = get_common_args(parser, ospdir)

    options = parser.parse_args()
    ospd_ovaldi = OSPDOvaldi(port=cargs['port'], timeout=cargs['timeout'],
                             keyfile=cargs['keyfile'], certfile=cargs['certfile'],
                             cafile=cargs['cafile'], debug=cargs['debug'],
                             address=cargs['address'])
    if not ospd_ovaldi.check():
        exit(1)
    ret = ospd_ovaldi.run()
    exit(ret)
