# $Id$
# Description:
# Miscellaneous classes and functions related to OSPD.
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
#/

""" Miscellaneous functions and utilities related to OSPD. """

import uuid
import datetime
import argparse
import os
import syslog

KEY_FILE = "/usr/var/lib/openvas/private/CA/clientkey.pem"
CERT_FILE = "/usr/var/lib/openvas/CA/clientcert.pem"
CA_FILE = "/usr/var/lib/openvas/CA/cacert.pem"
PORT = 1234
ADDRESS = "0.0.0.0"

class OSPLogger(object):
    """ Class to handle outputting log, debug and error messages. """

    def __init__(self, level=0):
        """ Initialize the instance. """
        self.level = level

    def set_level(self, level):
        """ Set the debugging level. """
        self.level = level

    def get_level(self):
        """ Get the debugging level. """
        return self.level

    def debug(self, level, message):
        """ Output a debug message if the provided level is equal or higher than
        the logger's.

        """
        if self.level >= level:
            self.__print_message('DEBUG: {0}'.format(message))

    def error(self, message):
        """ Output an error message. """
        self.__print_message('ERROR: {0}'.format(message))

    def __print_message(self, message):
        """ Prints a message to stdout. """
        assert message
        print message

class SyslogLogger(OSPLogger):

    def __init__(self, level=0):
        """ Initializes the syslog logger object. """
        super(SyslogLogger, self).__init__(level)
        syslog.openlog(ident="ospd")

    def debug(self, level, message):
        """ Send a debug message to syslog if the level is adequate. """
        if self.level >= level:
            syslog.syslog(syslog.LOG_DEBUG, message)

    def error(self, message):
        """ Send an error message to syslog. """
        syslog.syslog(syslog.LOG_ERR, message)

class ScanCollection(object):
    """ Scans collection, managing scans and results read and write, exposing
    only needed information.

    Each scan has meta-information such as scan ID, current progress (from 0 to
    100), start time, end time, scan target and options and a list of results.

    There are 3 types of results: Alarms, Logs and Errors.

    Todo:
    - Better checking for Scan ID existence and handling otherwise.
    - More data validation.
    - Mutex access per table/scan_info.

    """

    def __init__(self):
        """ Initialize the Scan Collection. """

        self.scans_table = dict()

    def add_alarm(self, scan_id, name="", value=""):
        """ Add a result of type Alarm to a scan in the table. """

        self.scans_table[scan_id]['results'].append((ResultType.ALARM, name,
                                                     value))

    def add_log(self, scan_id, name="", value=""):
        """ Add a result of type Log to a scan in the table. """

        self.scans_table[scan_id]['results'].append((ResultType.LOG, name,
                                                     value))

    def add_error(self, scan_id, name="", value=""):
        """ Add a result of type Error to a scan in the table. """

        self.scans_table[scan_id]['results'].append((ResultType.ERROR, name,
                                                     value))

    def set_progress(self, scan_id, progress):
        """ Sets scan_id scan's progress. """

        if progress > 0 and progress <= 100:
            self.scans_table[scan_id]['progress'] = progress
        if progress == 100:
            self.scans_table[scan_id]['end_time']\
             = datetime.datetime.now().strftime('%s')

    def results_iterator(self, scan_id):
        """ Returns an iterator over scan_id scan's results. """

        return iter(self.scans_table[scan_id]['results'])

    def ids_iterator(self):
        """ Returns an iterator over the collection's scan IDS. """

        return iter(self.scans_table.keys())

    def create_scan(self, target, options):
        """ Creates a new scan with provided target and options. """

        scan_info = dict()
        scan_info['results'] = list()
        scan_info['progress'] = 0
        scan_info['target'] = target
        scan_info['options'] = options
        scan_info['start_time'] = datetime.datetime.now().strftime('%s')
        scan_info['end_time'] = "0"
        scan_id = str(uuid.uuid4())
        scan_info['scan_id'] = scan_id
        self.scans_table[scan_id] = scan_info
        return scan_id

    def get_options(self, scan_id):
        """ Get scan_id scan's options list. """

        return self.scans_table[scan_id]['options']

    def set_option(self, scan_id, name, value):
        """ Set a scan_id scan's name option to value. """

        self.scans_table[scan_id]['options'][name] = value

    def get_progress(self, scan_id):
        """ Get a scan's current progress value. """

        return self.scans_table[scan_id]['progress']

    def get_start_time(self, scan_id):
        """ Get a scan's start time. """

        return self.scans_table[scan_id]['start_time']

    def get_end_time(self, scan_id):
        """ Get a scan's end time. """

        return self.scans_table[scan_id]['end_time']

    def get_target(self, scan_id):
        """ Get a scan's target. """

        return self.scans_table[scan_id]['target']

    def id_exists(self, scan_id):
        """ Check whether a scan exists in the table. """

        return self.scans_table.get(scan_id) is not None

    def delete_scan(self, scan_id):
        """ Delete a scan if fully finished. """

        if self.get_progress(scan_id) < 100:
            return False
        self.scans_table.pop(scan_id)
        return True

class ResultType(object):
    """ Various scan results types values. """

    ALARM = 0
    LOG = 1
    ERROR = 2

    @classmethod
    def get_str(cls, result_type):
        """ Return string name of a result type. """
        if result_type == cls.ALARM:
            return "Alarm"
        elif result_type == cls.LOG:
            return "Log Message"
        elif result_type == cls.ERROR:
            return "Error Message"
        else:
            assert False, "Erroneous result type {0}.".format(result_type)

    @classmethod
    def get_type(cls, result_name):
        """ Return string name of a result type. """
        if result_name == "Alarm":
            return cls.ALARM
        elif result_name == "Log Message":
            return cls.LOG
        elif result_name == "Error Message":
            return cls.ERROR
        else:
            assert False, "Erroneous result name {0}.".format(result_name)

def create_args_parser(description="OpenVAS's OSP Ovaldi Daemon."):
    """ Create a command-line arguments parser for OSPD. """

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-p', '--port', dest='port', type=int, nargs=1,
                        help='TCP Port to listen on. Default: {0}'.format(PORT))
    parser.add_argument('-b', '--bind-address', dest='address', type=str,
                        nargs=1, help='Address to listen on.'\
                                      ' Default: {0}'.format(ADDRESS))
    parser.add_argument('-k', '--key-file', dest='keyfile', type=str, nargs=1,
                        help='Server key file. Default: {0}'.format(KEY_FILE))
    parser.add_argument('-c', '--cert-file', dest='certfile', type=str, nargs=1,
                        help='Server cert file. Default: {0}'.format(CERT_FILE))
    parser.add_argument('--ca-file', dest='cafile', type=str, nargs=1,
                        help='CA cert file. Default: {0}'.format(CA_FILE))
    parser.add_argument('-d', '--debug', dest='debug', type=int, nargs=1,
                        help='Debug level. Default: 0')
    parser.add_argument('--syslog', dest='syslog', action='store_true',
                        help='Use syslog for logging.')

    return parser

def get_common_args(parser):
    """ Return list of OSPD common command-line arguments from parser, after
    validating provided values or setting default ones.

    """

    # TCP Port to listen on.
    options = parser.parse_args()
    port = PORT
    if options.port:
        port = int(options.port[0])
        if port <= 0 or port > 65535:
            print "--port must be in ]0,65535] interval.\n"
            parser.print_help()
            exit(1)

    # Network address to bind listener to
    address = ADDRESS
    if options.address:
        address = options.address[0]

    # Debug level.
    debug = 0
    if options.debug:
        debug = int(options.debug[0])
        if debug < 0 or debug > 2:
            print "--debug must be 0, 1 or 2.\n"
            parser.print_help()
            exit(1)

    # Server key path.
    keyfile = KEY_FILE
    if options.keyfile:
        keyfile = options.keyfile[0]
    if not os.path.isfile(keyfile):
        print "{0}: Server key file not found.".format(keyfile)
        print "You can generate one using openvas-mkcert."
        parser.print_help()
        exit(1)

    # Server cert path.
    certfile = CERT_FILE
    if options.certfile:
        certfile = options.certfile[0]
    if not os.path.isfile(certfile):
        print "{0}: Server cert file not found.\n".format(certfile)
        print "You can generate one using openvas-mkcert."
        parser.print_help()
        exit(1)

    # CA cert path.
    cafile = CA_FILE
    if options.cafile:
        cafile = options.cafile[0]
    if not os.path.isfile(cafile):
        print "{0}: CA cert file not found.\n".format(cafile)
        print "You can generate one using openvas-mkcert."
        parser.print_help()
        exit(1)

    common_args = dict()
    common_args['port'] = port
    common_args['address'] = address
    common_args['keyfile'] = keyfile
    common_args['certfile'] = certfile
    common_args['cafile'] = cafile
    common_args['debug'] = debug
    common_args['syslog'] = options.syslog

    return common_args
