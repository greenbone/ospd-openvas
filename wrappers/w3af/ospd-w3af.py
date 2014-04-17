#!/usr/bin/env python

# $Id$
# Description:
# w3af_console wrapper for OSPD.
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

import os
import inspect
from xml.dom.minidom import parse as xml_parse

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

# ospd-w3af class.
class OSPDw3af(OSPDaemon):
    """ Class for ospd-w3af daemon. """

    def __init__(self, certfile, keyfile, cafile, timeout, debug, port,
                 address):
        """ Initializes the ospd-w3af daemon's internal data. """
        super(OSPDw3af, self).__init__(certfile=certfile, keyfile=keyfile,
                                       cafile=cafile, timeout=timeout,
                                       debug=debug, port=port, address=address)

        self.version = "0.0.1"
        self.w3af_path = 'w3af_console'
        self.set_command_elements("start_scan", {'profile': 'w3af scan profile'})

    def check(self):
        """ Checks that w3af_console is found and is executable. """
        try:
            output = pexpect.spawn('w3af_console')
        except pexpect.ExceptionPexpect, message:
            self.logger.error(message)
            return False
        return True

    def get_w3af_version(self):
        """ Finds w3af scanner's version is executable """
        output = pexpect.spawn('w3af_console --version')
        output.expect(pexpect.EOF)
        for line in output.before.split('\n'):
            if line.startswith("Version: "):
                return line.split()[1]
        return "Parsing error."

    def get_scanner_name(self):
        """ Gives the used scanner's name. """
        return "w3af"

    def get_scanner_version(self):
        """ Gives the used scanner's version. """
        return self.get_w3af_version()

    def handle_start_scan_command(self, scan_et):
        """ Handles the OSP <start_scan> command element tree. """

        target = scan_et.attrib.get('target')
        if target is None:
            return "<start_scan status='400' status_text='No target attribute'/>"

        options = dict()
        profile = scan_et.find('profile')
        if profile is None:
            options['profile'] = 'fast_scan'
        else:
            options['profile'] = profile.text
        # Create new Scan
        scan_id = self.create_scan(target, options)

        # Start Scan
        self.start_scan(scan_id)

        # Return Response
        return self.create_response_string({'start_scan_response status="200"'
                                            ' status_text="OK"' :
                                             {'id' : scan_id}})

    def create_w3af_script(self, scan_id, output_file, options):
        """ Returns path to a w3af script file for the scan_id scan. """

        # XXX Maybe at init time, start w3af and query for available profiles ?
        profiles = ["bruteforce", "audit_high_risk", "full_audit",
                    "OWASP_TOP10", "fast_scan", "empty_profile",
                    "web_infrastructure", "full_audit_spider_man",
                    "sitemap"]
        profile = options.get('profile')
        if profile not in profiles:
            self.logger.debug(1, "Erroneous w3af profile {0}. Fall-back to fast_scan".format(profile))
            profile = 'fast_scan'
            self.set_scan_option(scan_id, 'profile', profile)
        else:
            self.logger.debug(2, "w3af scan using {0} profile.".format(profile))

        target = self.get_scan_target(scan_id)
        script_file = "/tmp/w3af-{0}".format(scan_id)
        with open(script_file, 'w') as f:
            f.write("profiles use {0}\n".format(profile))
            f.write("target set target {0}\n".format(target))
            f.write("plugins\n")
            f.write("output xml_file\n")
            f.write("output config xml_file\n")
            f.write("set output_file {0}\n".format(output_file))
            f.write("back\n")
            f.write("back\n")
            f.write("start\n")
        return script_file

    def exec_scan(self, scan_id):
        """ Starts the w3af scanner for scan_id scan. """

        output_file = "/tmp/w3af-scan-{1}".format(ospdir, scan_id)
        options = self.get_scan_options(scan_id)
        script_file = self.create_w3af_script(scan_id, output_file, options)
        # Spawn process
        output = pexpect.spawn('{0} -s {1}'.format(self.w3af_path, script_file))
        output.timeout = self.timeout
        try:
            output.expect("Scan finished in ")
            output.expect("w3af>>>")
        except pexpect.TIMEOUT:
            self.logger.debug(1, "w3af scan reached timeout.")
            self.handle_timeout(scan_id)
            os.remove(script_file)
            output.close(True)
            return

        # Now, parse output_file and make multiple results
        # Small delay.
        self.store_scan_results(scan_id, output_file)

        # Cleanup
        os.remove(output_file)
        os.remove(script_file)
        # Set scan as finished
        self.finish_scan(scan_id)

    def store_scan_results(self, scan_id, output_file):
        """ Stores scan results from the XML output_file """

        xmldoc = xml_parse(output_file)
        # w3afrun/vulnerability => result_type.ALERT
        vulns = xmldoc.getElementsByTagName('vulnerability')
        for vuln in vulns:
            desc = vuln.getElementsByTagName('description')[0]
            self.add_scan_alert(scan_id, value=desc.childNodes[0].nodeValue)
        # w3afrun/information => result_type.LOG
        information = xmldoc.getElementsByTagName('information')
        for info in information:
            desc = info.getElementsByTagName('description')[0]
            self.add_scan_log(scan_id, value=desc.childNodes[0].nodeValue)
        # w3afrun/error => result_type.ERROR
        errors = xmldoc.getElementsByTagName('error')
        for error in errors:
            # Error text is directly within node, not within <description>
            self.add_scan_error(scan_id, value=error.childNodes[0].nodeValue)

# Main starts here
if __name__ == '__main__':
    # Common args parser.
    parser = create_args_parser("OSPD - w3af_console wrapper")

    # Common args
    cargs = get_common_args(parser, ospdir)
    ospd_w3af = OSPDw3af(port=cargs['port'], timeout=cargs['timeout'],
                         keyfile=cargs['keyfile'], certfile=cargs['certfile'],
                         cafile=cargs['cafile'], debug=cargs['debug'],
                         address=cargs['address'])

    if not ospd_w3af.check():
        exit(1)
    ret = ospd_w3af.run()
    exit(ret)
