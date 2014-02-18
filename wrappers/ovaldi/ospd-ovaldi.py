#!/usr/bin/env python

# $Id$
# Description:
# remote-ovaldi wrapper for OSPD.
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

# Set OSPD Directory in syspaths, for imports
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
ospdir = os.path.dirname(os.path.dirname(currentdir))
os.sys.path.insert(0, ospdir)
# Local imports
from ospd.ospd import OSPDaemon
from ospd.misc import create_args_parser, get_common_args

# External modules.
try:
    import pexpect
except:
    print "pexpect not found."
    print "# pip install pexpect. (Or apt-get install python-pexpect.)"
    exit(1)

# ospd-ovaldi daemon class.
class OSPDOvaldi(OSPDaemon):
    """ Class for ospd-ovaldi daemon. """

    def __init__(self, certfile, keyfile, cafile, timeout, debug, defsfile,
                 rovaldi_path, port, address):
        """ Initializes the ospd-ovaldi daemon's internal data. """
        super(OSPDOvaldi, self).__init__(certfile=certfile, keyfile=keyfile,
                                         timeout=timeout, debug=debug,
                                         port=port, address=address)

        self.defs_path = defsfile
        self.version = "0.0.1"
        self.rovaldi_path = rovaldi_path
        self.set_command_elements("start_scan",
                                  {'username' : 'SSH Username for remote-ovaldi.',
                                   'password' : 'SSH Password for remote-ovaldi.',
                                   'port' : 'SSH Port for remote-ovaldi.'})

    def check(self):
        """ Checks that remote-ovaldi.sh is found and is executable. """
        try:
            output = pexpect.spawn(self.rovaldi_path)
        except pexpect.ExceptionPexpect, message:
            self.logger.error(message)
            return False
        return True

    def get_scanner_name(self):
        """ Gives the used scanner's name. """
        return "remote-ovaldi"

    def get_scanner_version(self):
        """ Gives the used scanner's version. """
        return "poc" # remote-ovaldi has no version.

    def handle_start_scan_command(self, scan_et):
        """ Handles the OSP <start_scan> command element tree. """
        # Validate scan information
        target = scan_et.attrib.get('target')
        if target is None:
            return "<start_scan status='400' status_text='No target attribute'/>"

        username = scan_et.find('username')
        if username is None or username.text is None:
            return "<start_scan status='400' status_text='No username element'/>"

        password = scan_et.find('password')
        if password is None or password.text is None:
            return "<start_scan status='400' status_text='No password element'/>"
        username = username.text
        password = password.text

        # Default port: 22.
        port = scan_et.find('port')
        if port is None:
            port = 22
        else:
            try:
                port = int(port.text)
            except ValueError:
                return "<start_scan status='400' status_text='Invalid port value'/>"

        options = dict()
        options['username'] = username
        options['password'] = password
        options['port'] = port

        # Create new Scan
        scan_id = self.create_scan(target, options)

        # Start Scan
        self.start_scan(scan_id)

        # Return Response
        return self.create_response_string({'start_scan_response status="200"'
                                            ' status_text="OK"' :
                                             {'id' : scan_id}})

    def exec_scanner(self, scan_id):
        """ Starts the ovaldi scanner for scan_id scan. """
        options = self.get_scan_options(scan_id)
        target = self.get_scan_target(scan_id)
        username = options['username']
        port = options['port']
        password = options['password']
        results_dir = '/tmp/ovaldi-results-{0}'.format(scan_id)

        # Pexpect
        output = pexpect.spawn('{0} -u {1} -h {2} -p {3} -o {4}'
                               ' --results-dir {5}/'
                                .format(self.rovaldi_path, username, target,
                                        port, self.defs_path, results_dir))
        output.timeout = self.timeout

        # Provide password for temp dir creation.
        try:
            output.expect("password:")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "ovaldi timeout waiting for temp dir creation prompt.")
            self.handle_timeout(scan_id)
            shutil.rmtree(results_dir)
            return
        except pexpect.EOF:
            # SSH Connection failed.
            for line in output.before.split('\n'):
                if "[ERROR]" in line:
                    self.add_scan_error(scan_id, line)
                    self.set_scan_progress(scan_id, 100)
            self.set_scan_progress(scan_id, 100)
            try:
                shutil.rmtree(results_dir)
            except OSError:
                pass
            return
        output.sendline("{0}".format(password))

        # Provide password for scp setup script to remote host
        try:
            output.expect("password:")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "ovaldi timeout waiting for scp to remote host prompt.")
            self.handleTimeout(scan_id)
            return
        output.sendline("{0}".format(password))

        # Provide password for making script executable
        try:
            output.expect("password:")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "ovaldi timeout waiting for making script executable prompt.")
            self.handleTimeout(scan_id)
            return
        output.sendline("{0}".format(password))

        # Provide password for running setup script on remote
        try:
            output.expect("password:")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "ovaldi timeout waiting for running setup script prompt.")
            self.handleTimeout(scan_id)
            return
        output.sendline("{0}".format(password))

        # Provide password for copying input files to remote
        try:
            output.expect("password:")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "ovaldi timeout waiting for copying input files prompt.")
            self.handleTimeout(scan_id)
            return
        output.sendline("{0}".format(password))

        # Provide password for running ovaldi on remote host
        try:
            output.expect("password:")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "ovaldi timeout waiting for running ovaldi prompt.")
            self.handleTimeout(scan_id)
            return
        except pexpect.EOF:
            # Happens when ovaldi is not installed on remote host.
            self.add_scan_error(scan_id, "ovaldi not present on remote host.")
            self.set_scan_progress(scan_id, 100)
            # Delete empty results directory
            shutil.rmtree(results_dir)
            return
        output.sendline("{0}".format(password))

        # Provide password for copying results from remote host
        try:
            output.expect("password:")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "ovaldi timeout waiting for results copying prompt.")
            self.handleTimeout(scan_id)
            return
        output.sendline("{0}".format(password))

        # Provide password for cleaning up temp directory
        try:
            output.expect("password:")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "ovaldi timeout waiting for temp dir clean-up prompt.")
            self.handleTimeout(scan_id)
            return
        output.sendline("{0}".format(password))

        # The end
        output.expect(pexpect.EOF)

        try:
            # XXX Extract/Reorganize/Filter/Trim files content to multiple
            # results.

            # Get ovaldi.log
            with open("{0}/ovaldi.log".format(results_dir), 'r') as f:
                log_content = f.read()
            self.add_scan_log(scan_id, log_content)

            # Get result.xml
            with open("{0}/result.xml".format(results_dir), 'r') as f:
                log_content = f.read()
            self.add_scan_alert(scan_id, log_content)
            # Get oval_syschar.xml
            with open("{0}/oval_syschar.xml".format(results_dir), 'r') as f:
                log_content = f.read()
            self.add_scan_alert(scan_id, log_content)
        except IOError:
            # One case where *.xml files are missing: Definitions file doesn't
            # match ovaldi version or its schema is not valid, thus only
            # ovaldi.log was generated and no further scan occured.
            self.logger.debug(1, "Couldn't open results file in {0}".format(results_dir))
            pass

        # Clean up the results folder etc,.
        shutil.rmtree(results_dir)

        # Set scan as finished
        self.set_scan_progress(scan_id, 100)

# Main starts here
if __name__ == '__main__':
    # Common args parser.
    parser = create_args_parser("OSPD - Remote Ovaldi wrapper")

    # ospd-ovaldi specific.
    parser.add_argument('-D', '--defs-file', dest='defsfile', type=str, nargs=1,
                        help='OVAL Definitions file.'
                             ' (Default is definitions.xml)')
    parser.add_argument('--remote-ovaldi', dest='rovaldi', type=str, nargs=1,
                        help='remote-ovaldi.sh path.'
                             ' (Default is remote-ovaldi.sh)')
    # Common args
    cargs = get_common_args(parser, ospdir)

    # Check for Ovaldi definitions file
    options = parser.parse_args()
    if options.defsfile:
        defsfile = options.defsfile[0]
    else:
        defsfile = "{0}/definitions.xml".format(ospdir)
    if not os.path.isfile(defsfile):
        print "{0}: ovaldi definitions file not found.".format(defsfile)
        print "Some are available on http://oval.mitre.org/"
        print "\n"
        parser.print_help()
        exit(1)

    # Check for Remote Ovaldi script
    if options.rovaldi:
        rovaldi = options.rovaldi[0]
    else:
        rovaldi = "{0}/wrappers/ovaldi/remote-ovaldi.sh".format(ospdir)
    if not os.path.isfile(rovaldi):
        print "{0}: script not found.".format(rovaldi)
        print "\n"
        parser.print_help()
        exit(1)

    ospd_ovaldi = OSPDOvaldi(port=cargs['port'], timeout=cargs['timeout'],
                             keyfile=cargs['keyfile'], certfile=cargs['certfile'],
                             cafile=cargs['cafile'],
                             debug=cargs['debug'], defsfile=defsfile,
                             rovaldi_path=rovaldi, address=cargs['address'])
    if not ospd_ovaldi.check():
        exit(1)
    ret = ospd_ovaldi.run()
    exit(ret)
