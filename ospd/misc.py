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

import argparse
import datetime
import logging
import logging.handlers
import os
import sys
import uuid
import socket
import struct
import binascii

logger = logging.getLogger(__name__)

KEY_FILE = "/usr/var/lib/openvas/private/CA/clientkey.pem"
CERT_FILE = "/usr/var/lib/openvas/CA/clientcert.pem"
CA_FILE = "/usr/var/lib/openvas/CA/cacert.pem"
PORT = 1234
ADDRESS = "0.0.0.0"


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

    def add_result(self, scan_id, result_type, host='', name='', value='',
                   severity=''):
        """ Add a result to a scan in the table. """

        assert scan_id
        result = dict()
        result['type'] = result_type
        result['name'] = name
        result['severity'] = severity
        result['value'] = value
        result['host'] = host
        self.scans_table[scan_id]['results'].append(result)

    def add_alarm(self, scan_id, host='', name='', value='', severity=''):
        """ Add a result of type Alarm to a scan in the table. """
        self.add_result(scan_id, ResultType.ALARM, host, name, value, severity)

    def add_log(self, scan_id, host='', name='', value=''):
        """ Add a result of type Log to a scan in the table. """
        self.add_result(scan_id, ResultType.LOG, host, name, value, '')

    def add_error(self, scan_id, host='', name='', value=''):
        """ Add a result of type Error to a scan in the table. """
        self.add_result(scan_id, ResultType.ERROR, host, name, value, '')

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
        scan_info['exec_thread'] = None
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

    def get_thread(self, scan_id):
        """ Get a scan's executing thread. """
        return self.scans_table[scan_id]['exec_thread']

    def set_thread(self, scan_id, thread):
        """ Set a scan's executing thread. """
        self.scans_table[scan_id]['exec_thread'] = thread

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

def target_to_ipv4(target):
    try:
        socket.inet_pton(socket.AF_INET, target)
        return [target]
    except:
        return None

def target_to_ipv6(target):
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return [target]
    except:
        return None

def ipv4_range_to_list(start_packed, end_packed):
    new_list = list()
    try:
        start = struct.unpack('!L', start_packed)[0]
        end = struct.unpack('!L', end_packed)[0]
        for value in xrange(start, end + 1):
            new_ip = socket.inet_ntoa(struct.pack('!L', value))
            new_list.append(new_ip)
    except:
        return None
    return new_list

def target_to_ipv4_short(target):
    splitted = target.split('-')
    if len(splitted) != 2:
        return None
    try:
        start_packed = socket.inet_pton(socket.AF_INET, splitted[0])
        start_value = int(binascii.hexlify(start_packed[3]), 16)
        end_value = int(splitted[1])
        if end_value < 0 or end_value > 255 or end_value < start_value:
            return None
        end_packed = start_packed[0:3] + struct.pack('B', end_value)
        return ipv4_range_to_list(start_packed, end_packed)
    except:
        return None

def target_to_ipv4_long(target):
    splitted = target.split('-')
    if len(splitted) != 2:
        return None
    try:
        start_packed = socket.inet_pton(socket.AF_INET, splitted[0])
        end_packed = socket.inet_pton(socket.AF_INET, splitted[1])
        if end_packed < start_packed:
            return None
        return ipv4_range_to_list(start_packed, end_packed)
    except:
        return None

def target_to_list(target):
    # Is it an IPv4 address ?
    new_list = target_to_ipv4(target)
    if new_list:
        return new_list
    # Is it an IPv6 address ?
    new_list = target_to_ipv6(target)
    if new_list:
        return new_list
    # Is it an IPv4 short-range ?
    new_list = target_to_ipv4_short(target)
    if new_list:
        return new_list
    # Is it an IPv4 long-range ?
    new_list = target_to_ipv4_long(target)
    if new_list:
        return new_list
    return None

def target_str_to_list(target_str):
    """ Parses a targets string into a list of individual targets. """
    new_list = list()
    for target in target_str.split(','):
        target = target.strip()
        target_list = target_to_list(target)
        if target_list:
            new_list.extend(target_list)
        else:
            logger.info("{0}: Invalid target value".format(target))
            return None
    return new_list

def create_args_parser(description):
    """ Create a command-line arguments parser for OSPD. """

    parser = argparse.ArgumentParser(description=description)

    def network_port(string):
        value = int(string)
        if not (0 < value <= 65535):
            raise argparse.ArgumentTypeError('port must be in ]0,65535] interval')
        return value

    def log_level(string):
        value = getattr(logging, string.upper(), None)
        if not isinstance(value, int):
            raise argparse.ArgumentTypeError('log level must be one of {debug,info,warning,error,critical}')
        return value

    def filename(string):
        if not os.path.isfile(string):
            raise argparse.ArgumentTypeError('%s is not a valid file path' % string)
        return string

    parser.add_argument('-p', '--port', default=PORT, type=network_port,
                        help='TCP Port to listen on. Default: {0}'.format(PORT))
    parser.add_argument('-b', '--bind-address', default=ADDRESS,
                        help='Address to listen on. Default: {0}'.format(ADDRESS))
    parser.add_argument('-k', '--key-file', type=filename,
                        help='Server key file. Default: {0}'.format(KEY_FILE))
    parser.add_argument('-c', '--cert-file', type=filename,
                        help='Server cert file. Default: {0}'.format(CERT_FILE))
    parser.add_argument('--ca-file', type=filename,
                        help='CA cert file. Default: {0}'.format(CA_FILE))
    parser.add_argument('-L', '--log-level', default='warning', type=log_level,
                        help='Wished level of logging. Default: WARNING')
    parser.add_argument('--syslog', action='store_true',
                        help='Use syslog for logging.')
    parser.add_argument('--background', action='store_true',
                        help='Run in background.')
    parser.add_argument('--version', action='store_true',
                        help='Print version then exit.')
    return parser

def go_to_background():
    """ Daemonize the running process. """
    try:
        if os.fork():
            sys.exit()
    except OSError as errmsg:
        logger.error('Fork failed: {0}'.format(errmsg))
        sys.exit('Fork failed')

def get_common_args(parser, args=None):
    """ Return list of OSPD common command-line arguments from parser, after
    validating provided values or setting default ones.

    """

    options = parser.parse_args(args)
    # TCP Port to listen on.
    port = options.port

    # Network address to bind listener to
    address = options.bind_address

    # Debug level.
    log_level = options.log_level

    # Server key path.
    keyfile = options.key_file or KEY_FILE

    # Server cert path.
    certfile = options.cert_file or CERT_FILE

    # CA cert path.
    cafile = options.ca_file or CA_FILE

    common_args = dict()
    common_args['port'] = port
    common_args['address'] = address
    common_args['keyfile'] = keyfile
    common_args['certfile'] = certfile
    common_args['cafile'] = cafile
    common_args['log_level'] = log_level
    common_args['syslog'] = options.syslog
    common_args['background'] = options.background
    common_args['version'] = options.version

    return common_args

def print_version(wrapper):
    """ Prints the server version and license information."""

    scanner_name = wrapper.get_scanner_name()
    server_version = wrapper.get_server_version()
    print "OSP Server for {0} version {1}".format(scanner_name, server_version)
    protocol_version = wrapper.get_protocol_version()
    print  "OSP Version: {0}".format(protocol_version)
    daemon_name = wrapper.get_daemon_name()
    daemon_version = wrapper.get_daemon_version()
    print "Using: {0} {1}".format(daemon_name, daemon_version)
    print "Copyright (C) 2014 Greenbone Networks GmbH\n"\
          "License GPLv2+: GNU GPL version 2 or later\n"\
          "This is free software: you are free to change"\
          " and redistribute it.\n"\
          "There is NO WARRANTY, to the extent permitted by law."

def main(name, klass):
    # Common args parser.
    parser = create_args_parser(name)

    # Common args
    cargs = get_common_args(parser)
    logging.getLogger().setLevel(cargs['log_level'])
    wrapper = klass(keyfile=cargs['keyfile'], certfile=cargs['certfile'],
                    cafile=cargs['cafile'])

    if cargs['version']:
        print_version(wrapper)
        sys.exit()
    if cargs['syslog']:
        syslog = logging.handlers.SysLogHandler('/dev/log')
        syslog.setFormatter(logging.Formatter('%(name)s: %(levelname)s: %(message)s'))
        logging.getLogger().addHandler(syslog)
    else:
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter('%(asctime)s %(name)s: %(levelname)s: %(message)s'))
        logging.getLogger().addHandler(console)

    if cargs['background']:
        go_to_background()

    if not wrapper.check():
        return 1
    return wrapper.run(cargs['address'], cargs['port'])
