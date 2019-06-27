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

    def log_level(string):
        """ Check if provided string is a valid log level. """

        value = getattr(logging, string.upper(), None)
        if not isinstance(value, int):
            raise argparse.ArgumentTypeError(
                'log level must be one of {debug,info,warning,error,critical}'
            )
        return value

    parser.add_argument(
        '--version', action='store_true', help='Print version then exit.'
    )

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
        default=DEFAULT_KEY_FILE,
        help='Server key file. Default: {0}'.format(DEFAULT_KEY_FILE),
    )
    parser.add_argument(
        '-c',
        '--cert-file',
        default=DEFAULT_CERT_FILE,
        help='Server cert file. Default: %(default)s',
    )
    parser.add_argument(
        '--ca-file',
        help='CA cert file. Default: %(default)s',
        default=DEFAULT_CA_FILE,
    )
    parser.add_argument(
        '-L',
        '--log-level',
        default='WARNING',
        type=log_level,
        help='Wished level of logging. Default: %(default)s',
    )
    parser.add_argument(
        '-f',
        '--foreground',
        action='store_true',
        help='Run in foreground and logs all messages to console.',
    )
    parser.add_argument('-l', '--log-file', help='Path to the logging file.')
    parser.add_argument(
        '--niceness',
        default=DEFAULT_NICENESS,
        type=int,
        help='Start the scan with the given niceness. Default %(default)s',
    )

    return parser
