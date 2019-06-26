# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

import argparse
import logging
import os
import ssl
import time

# Default file locations as used by a OpenVAS default installation
DEFAULT_KEY_FILE = "/usr/var/lib/gvm/private/CA/serverkey.pem"
DEFAULT_CERT_FILE = "/usr/var/lib/gvm/CA/servercert.pem"
DEFAULT_CA_FILE = "/usr/var/lib/gvm/CA/cacert.pem"

DEFAULT_PORT = 1234
DEFAULT_ADDRESS = "0.0.0.0"
DEFAULT_NICENESS = 10

ParserType = argparse.ArgumentParser


def create_args_parser(description: str) -> ParserType:
    """ Create a command-line arguments parser for OSPD. """

    parser = argparse.ArgumentParser(description=description)

    def network_port(string):
        """ Check if provided string is a valid network port. """

        value = int(string)
        if not 0 < value <= 65535:
            raise argparse.ArgumentTypeError(
                'port must be in ]0,65535] interval'
            )
        return value

    def cacert_file(cacert):
        """ Check if provided file is a valid CA Certificate """
        try:
            context = ssl.create_default_context(cafile=cacert)
        except AttributeError:
            # Python version < 2.7.9
            return cacert
        except IOError:
            raise argparse.ArgumentTypeError('CA Certificate not found')
        try:
            not_after = context.get_ca_certs()[0]['notAfter']
            not_after = ssl.cert_time_to_seconds(not_after)
            not_before = context.get_ca_certs()[0]['notBefore']
            not_before = ssl.cert_time_to_seconds(not_before)
        except (KeyError, IndexError):
            raise argparse.ArgumentTypeError('CA Certificate is erroneous')
        if not_after < int(time.time()):
            raise argparse.ArgumentTypeError('CA Certificate expired')
        if not_before > int(time.time()):
            raise argparse.ArgumentTypeError('CA Certificate not active yet')
        return cacert

    def log_level(string):
        """ Check if provided string is a valid log level. """

        value = getattr(logging, string.upper(), None)
        if not isinstance(value, int):
            raise argparse.ArgumentTypeError(
                'log level must be one of {debug,info,warning,error,critical}'
            )
        return value

    def filename(string):
        """ Check if provided string is a valid file path. """

        if not os.path.isfile(string):
            raise argparse.ArgumentTypeError(
                '%s is not a valid file path' % string
            )
        return string

    parser.add_argument(
        '-p',
        '--port',
        default=DEFAULT_PORT,
        type=network_port,
        help='TCP Port to listen on. Default: %(default)s',
    )
    parser.add_argument(
        '-b',
        '--bind-address',
        default=DEFAULT_ADDRESS,
        dest='address',
        help='Address to listen on. Default: %(default)s',
    )
    parser.add_argument(
        '-u', '--unix-socket', help='Unix file socket to listen on.'
    )
    parser.add_argument(
        '-k',
        '--key-file',
        type=filename,
        help='Server key file. Default: {0}'.format(DEFAULT_KEY_FILE),
    )
    parser.add_argument(
        '-c',
        '--cert-file',
        type=filename,
        help='Server cert file. Default: {0}'.format(DEFAULT_CERT_FILE),
    )
    parser.add_argument(
        '--ca-file',
        type=cacert_file,
        help='CA cert file. Default: {0}'.format(DEFAULT_CA_FILE),
    )
    parser.add_argument(
        '-L',
        '--log-level',
        default='WARNING',
        type=log_level,
        help='Wished level of logging. Default: %(default)s',
    )
    parser.add_argument(
        '--foreground',
        action='store_true',
        help='Run in foreground and logs all messages to console.',
    )
    parser.add_argument(
        '-l', '--log-file', type=filename, help='Path to the logging file.'
    )
    parser.add_argument(
        '--version', action='store_true', help='Print version then exit.'
    )
    parser.add_argument(
        '--niceness',
        default=DEFAULT_NICENESS,
        type=int,
        help='Start the scan with the given niceness. Default %(default)s',
    )

    return parser


def get_common_args(parser, args=None):
    """ Return list of OSPD common command-line arguments from parser, after
    validating provided values or setting default ones.

    """

    options = parser.parse_args(args)
    # TCP Port to listen on.
    port = options.port

    # Network address to bind listener to
    address = options.bind_address

    # Unix file socket to listen on
    unix_socket = options.unix_socket

    # Debug level.
    log_level = options.log_level

    # Server key path.
    keyfile = options.key_file or DEFAULT_KEY_FILE

    # Server cert path.
    certfile = options.cert_file or DEFAULT_CERT_FILE

    # CA cert path.
    cafile = options.ca_file or DEFAULT_CA_FILE

    common_args = dict()
    common_args['port'] = port
    common_args['address'] = address
    common_args['unix_socket'] = unix_socket
    common_args['keyfile'] = keyfile
    common_args['certfile'] = certfile
    common_args['cafile'] = cafile
    common_args['log_level'] = log_level
    common_args['foreground'] = options.foreground
    common_args['log_file'] = options.log_file
    common_args['version'] = options.version
    common_args['niceness'] = options.niceness

    return common_args
