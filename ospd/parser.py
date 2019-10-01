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
from pathlib import Path

from ospd.config import Config

# Default file locations as used by a OpenVAS default installation
DEFAULT_KEY_FILE = "/usr/var/lib/gvm/private/CA/serverkey.pem"
DEFAULT_CERT_FILE = "/usr/var/lib/gvm/CA/servercert.pem"
DEFAULT_CA_FILE = "/usr/var/lib/gvm/CA/cacert.pem"

DEFAULT_PORT = 0
DEFAULT_ADDRESS = "0.0.0.0"
DEFAULT_NICENESS = 10
DEFAULT_UNIX_SOCKET_MODE = "0o700"
DEFAULT_CONFIG_PATH = "~/.config/ospd.conf"
DEFAULT_UNIX_SOCKET_PATH = "/var/run/ospd/ospd.sock"
DEFAULT_PID_PATH = "/var/run/ospd.pid"
DEFAULT_STREAM_TIMEOUT = 10  # ten seconds

ParserType = argparse.ArgumentParser
Arguments = argparse.Namespace

logger = logging.getLogger(__name__)


class CliParser:
    def __init__(self, description):
        """ Create a command-line arguments parser for OSPD. """
        self._name = description
        parser = argparse.ArgumentParser(description=description)

        parser.add_argument(
            '--version', action='store_true', help='Print version then exit.'
        )

        parser.add_argument(
            '-s',
            '--config',
            nargs='?',
            default=DEFAULT_CONFIG_PATH,
            help='Configuration file path (default: %(default)s)',
        )

        parser.add_argument(
            '-p',
            '--port',
            default=DEFAULT_PORT,
            type=self.network_port,
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
            '-u',
            '--unix-socket',
            default=DEFAULT_UNIX_SOCKET_PATH,
            help='Unix file socket to listen on. Default: %(default)s',
        )
        parser.add_argument(
            '--pid-file',
            default=DEFAULT_PID_PATH,
            help='Unix file socket to listen on.'
        )

        parser.add_argument(
            '-m',
            '--socket-mode',
            default=DEFAULT_UNIX_SOCKET_MODE,
            help='Unix file socket mode. Default: %(default)s',
        )

        parser.add_argument(
            '-k',
            '--key-file',
            default=DEFAULT_KEY_FILE,
            help='Server key file. Default: %(default)s',
        )
        parser.add_argument(
            '-c',
            '--cert-file',
            default=DEFAULT_CERT_FILE,
            help='Server cert file. Default: %(default)s',
        )
        parser.add_argument(
            '--ca-file',
            default=DEFAULT_CA_FILE,
            help='CA cert file. Default: %(default)s',
        )
        parser.add_argument(
            '-L',
            '--log-level',
            default='WARNING',
            type=self.log_level,
            help='Wished level of logging. Default: %(default)s',
        )
        parser.add_argument(
            '-f',
            '--foreground',
            action='store_true',
            help='Run in foreground and logs all messages to console.',
        )
        parser.add_argument(
            '-t',
            '--stream-timeout',
            default=DEFAULT_STREAM_TIMEOUT,
            type=int,
            help='Stream timeout. Default: %(default)s',
        )
        parser.add_argument(
            '-l', '--log-file', help='Path to the logging file.'
        )
        parser.add_argument(
            '--niceness',
            default=DEFAULT_NICENESS,
            type=int,
            help='Start the scan with the given niceness. Default %(default)s',
        )

        self.parser = parser

    def network_port(self, string):
        """ Check if provided string is a valid network port. """

        value = int(string)
        if not 0 < value <= 65535:
            raise argparse.ArgumentTypeError(
                'port must be in ]0,65535] interval'
            )
        return value

    def log_level(self, string):
        """ Check if provided string is a valid log level. """

        value = getattr(logging, string.upper(), None)
        if not isinstance(value, int):
            raise argparse.ArgumentTypeError(
                'log level must be one of {debug,info,warning,error,critical}'
            )
        return value

    def _set_defaults(self, configfilename=None):
        self._config = self._load_config(configfilename)
        self.parser.set_defaults(**self._config.defaults())

    def _load_config(self, configfile):
        config = Config()

        if not configfile:
            return config

        configpath = Path(configfile)

        try:
            if not configpath.expanduser().resolve().exists():
                logger.debug('Ignoring non existing config file %s', configfile)
                return config
        except FileNotFoundError:
            # we are on python 3.5 and Path.resolve raised a FileNotFoundError
            logger.debug('Ignoring non existing config file %s', configfile)
            return config

        try:
            config.load(configpath, def_section=self._name)
            logger.debug('Loaded config %s', configfile)
        except Exception as e:  # pylint: disable=broad-except
            raise RuntimeError(
                'Error while parsing config file {config}. Error was '
                '{message}'.format(config=configfile, message=e)
            )

        return config

    def parse_arguments(self, args=None):
        # Parse args to get the config file path passed as option
        _args, _ = self.parser.parse_known_args(args)

        # Load the defaults from the config file if it exists.
        # This override also what it was passed as cmd option.
        self._set_defaults(_args.config)
        args, _ = self.parser.parse_known_args(args)

        return args


def create_parser(description):
    return CliParser(description)
