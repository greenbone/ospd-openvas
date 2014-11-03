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

""" w3af wrapper for OSPD. """

import os
import inspect
from xml.dom.minidom import parse as xml_parse

# Set OSPD Directory in syspaths, for imports
CURRENT_DIR = os.path.dirname(os.path.abspath(inspect.getfile(inspect.\
                                                              currentframe())))
os.sys.path.insert(0, os.path.dirname(os.path.dirname(CURRENT_DIR)))
# Local imports
from ospd.ospd import OSPDaemon, simple_response_str
from ospd.misc import create_args_parser, get_common_args, OSPLogger
from ospd.misc import SyslogLogger, go_to_background

# External modules.
try:
    import pexpect
except ImportError:
    print "pexpect not found."
    print "# pip install pexpect. (Or apt-get install python-pexpect.)"
    exit(1)

OSPD_W3AF_DESCRIPTION = """
This scanner runs the 'w3af' scanner installed on the local system.

w3af is a Web Application Attack and Audit Framework. The project's goal is to
create a framework to help you secure web applications by finding and exploiting
all web application vulnerabilities.

For more information, see the w3af website:
    http://w3af.org/
"""

OSPD_W3AF_PARAMS = \
{'profile' :
 {'type' : 'string',
  'name' : 'Scan profile',
  'default' : 'fast_scan',
  'description' : 'Scan profiles are predefined set of plugins and'
                  ' customized configurations.',
 },
 'w3af_timeout' :
 {'type' : 'integer',
  'name' : 'w3af scan timeout',
  'default' : 3600,
  'description' : 'Time to wait for the w3af scan to finish.',
 },
 'target_port' :
 {'type' : 'integer',
  'name' : 'Target port',
  'default' : 80,
  'description' : 'Port on target host to scan',
 },
 'use_https' :
 {'type' : 'boolean',
  'name' : 'Use HTTPS',
  'default' : 0,
  'description' : 'Whether the target application is running over HTTPS',
 },
}

def get_w3af_version():
    """ Finds w3af scanner's version is executable """
    output = pexpect.spawn('w3af_console --version')
    output.expect(pexpect.EOF)
    for line in output.before.split('\n'):
        if line.startswith("Version: "):
            return line.split()[1]
    return "Parsing error."

# ospd-w3af class.
class OSPDw3af(OSPDaemon):
    """ Class for ospd-w3af daemon. """

    def __init__(self, certfile, keyfile, cafile):
        """ Initializes the ospd-w3af daemon's internal data. """
        super(OSPDw3af, self).__init__(certfile=certfile, keyfile=keyfile,
                                       cafile=cafile)
        self.init_scanner_params(OSPD_W3AF_PARAMS)

    def check(self):
        """ Checks that w3af_console is found and is executable. """
        try:
            output = pexpect.spawn('w3af_console')
            output.expect("w3af>>>")
        except pexpect.ExceptionPexpect, message:
            self.logger.error("Check for w3af_console failed")
            return False
        return True

    def get_scanner_name(self):
        """ Gives the used scanner's name. """
        return "w3af"

    def get_scanner_version(self):
        """ Gives the used scanner's version. """
        return get_w3af_version()

    def get_scanner_description(self):
        """ Gives the used scanner's description. """
        return OSPD_W3AF_DESCRIPTION

    def handle_start_scan_command(self, scan_et):
        """ Handles the OSP <start_scan> command element tree. """

        target = scan_et.attrib.get('target')
        if target is None:
            return simple_response_str('start_scan', 400, 'No target attribute')
        scanner_params = scan_et.find('scanner_params')
        if scanner_params is None:
            return simple_response_str('start_scan', 400,
                                       'No scanner_params element')
        options = dict()
        profile = scanner_params.find('profile')
        if profile is None or profile.text is None:
            profile = self.get_scanner_param_default('profile')
        else:
            profile = profile.text
        profiles = ["bruteforce", "audit_high_risk", "full_audit",
                    "OWASP_TOP10", "fast_scan", "empty_profile",
                    "web_infrastructure", "full_audit_spider_man", "sitemap"]
        if profile not in profiles:
            self.logger.debug(1, "Erroneous profile name {0}.".format(profile))
            return simple_response_str('start_scan', 400,
                                       'Invalid profile value')
        options['profile'] = profile
        timeout = scanner_params.find('w3af_timeout')
        if timeout is None or timeout.text is None:
            options['timeout'] = self.get_scanner_param_default('w3af_timeout')
        else:
            try:
                options['timeout'] = int(timeout.text)
                if options['timeout'] < 0:
                    raise ValueError
            except ValueError:
                return simple_response_str('start_scan', 400,
                                           'Invalid timeout value')
        port = scanner_params.find('target_port')
        if port is None or port.text is None:
            options['port'] = self.get_scanner_param_default('target_port')
        else:
            try:
                options['port'] = int(port.text)
                if options['port'] <= 0 or options['port'] > 65535:
                    raise ValueError
            except ValueError:
                return simple_response_str('start_scan', 400,
                                           'Invalid target_port value')
        use_https = scanner_params.find('use_https')
        if use_https is None or use_https.text is None:
            options['use_https'] = self.get_scanner_param_default('use_https')
        else:
            try:
                options['use_https'] = int(use_https.text)
                if options['use_https'] != 0 and options['use_https'] != 1:
                    raise ValueError
            except ValueError:
                return simple_response_str('start_scan', 400,
                                           'Invalid target_port value')
        # Create new Scan
        scan_id = self.create_scan(target, options)

        # Start Scan
        self.start_scan(scan_id)
        text = '<id>{0}</id>'.format(scan_id)
        return simple_response_str('start_scan', 200, 'OK', text)

    def create_w3af_script(self, scan_id, output_file, options):
        """ Returns path to a w3af script file for the scan_id scan. """

        profile = options.get('profile')
        self.logger.debug(2, "w3af scan using {0} profile.".format(profile))
        target = self.get_scan_target(scan_id)
        script_path = "/tmp/w3af-{0}".format(scan_id)
        port = options.get('port')
        with open(script_path, 'w') as file_path:
            file_path.write("profiles use {0}\n".format(profile))
            if options.get('use_https') == 0:
                target_url = 'http://{0}:{1}'.format(target, port)
            else:
                target_url = 'https://{0}:{1}'.format(target, port)
            file_path.write("target set target {0}\n".format(target_url))
            file_path.write("plugins\n")
            file_path.write("output xml_file\n")
            file_path.write("output config xml_file\n")
            file_path.write("set output_file {0}\n".format(output_file))
            file_path.write("back\n")
            file_path.write("back\n")
            file_path.write("start\n")
        return script_path

    def exec_scan(self, scan_id):
        """ Starts the w3af scanner for scan_id scan. """

        options = self.get_scan_options(scan_id)
        assert options.has_key('port')
        assert options.has_key('timeout')
        assert options.has_key('use_https')
        assert options.has_key('profile')

        output_file = "/tmp/w3af-scan-{0}".format(scan_id)
        script_file = self.create_w3af_script(scan_id, output_file, options)
        # Spawn process
        output = pexpect.spawn('w3af_console -s {0}'.format(script_file))
        output.timeout = options['timeout']
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
        if self.logger.get_level() < 1:
            os.remove(output_file)
        else:
            self.logger.debug(2, "{0} not removed.".format(output_file))
        os.remove(script_file)
        # Set scan as finished
        self.finish_scan(scan_id)

    def store_scan_results(self, scan_id, output_file):
        """ Stores scan results from the XML output_file """

        xmldoc = xml_parse(output_file)
        # w3afrun/vulnerability => result_type.ALARM
        vulns = xmldoc.getElementsByTagName('vulnerability')
        for vuln in vulns:
            vuln_name = vuln.getAttribute('name')
            severity = vuln.getAttribute('severity').lower()
            if severity == 'information':
                vuln_sev = '0.0'
            if severity == 'low':
                vuln_sev = '2.5'
            elif severity == 'medium':
                vuln_sev = '5.0'
            elif severity == 'high':
                vuln_sev = '7.5'
            else:
                self.logger.debug(1, "Unknown severity {0}.".format(severity))
                vuln_sev = ''
            desc_elem = vuln.getElementsByTagName('description')[0]
            vuln_desc = desc_elem.childNodes[0].nodeValue
            vuln_desc = vuln_desc.split("This vulnerability was found in ")[0]
            self.add_scan_alarm(scan_id, name=vuln_name, value=vuln_desc,
                                severity=vuln_sev)
        # w3afrun/information => result_type.LOG
        information = xmldoc.getElementsByTagName('information')
        for info in information:
            info_name = info.getAttribute('name')
            desc_elem = info.getElementsByTagName('description')[0]
            info_desc = desc_elem.childNodes[0].nodeValue
            info_desc = info_desc.split("This vulnerability was found in ")[0]
            info_desc = info_desc.split("This information was found in ")[0]
            self.add_scan_log(scan_id, name=info_name, value=info_desc)
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
    cargs = get_common_args(parser)
    ospd_w3af = OSPDw3af(keyfile=cargs['keyfile'], certfile=cargs['certfile'],
                         cafile=cargs['cafile'])
    if cargs['syslog']:
        ospd_w3af.set_logger(SyslogLogger(cargs['debug']))
    else:
        ospd_w3af.set_logger(OSPLogger(cargs['debug']))
    if cargs['background']:
        go_to_background(ospd_w3af.logger)

    if not ospd_w3af.check():
        exit(1)
    exit(ospd_w3af.run(cargs['address'], cargs['port']))
