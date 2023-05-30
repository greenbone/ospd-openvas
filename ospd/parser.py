# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import logging
from pathlib import Path

from ospd.config import Config

# Default file locations as used by a OpenVAS default installation
DEFAULT_KEY_FILE = "/var/lib/gvm/private/CA/serverkey.pem"
DEFAULT_CERT_FILE = "/var/lib/gvm/CA/servercert.pem"
DEFAULT_CA_FILE = "/var/lib/gvm/CA/cacert.pem"

DEFAULT_PORT = 0
DEFAULT_ADDRESS = "0.0.0.0"
DEFAULT_NICENESS = 10
DEFAULT_UNIX_SOCKET_MODE = "0o770"
DEFAULT_CONFIG_PATH = "~/.config/ospd.conf"
DEFAULT_LOG_CONFIG_PATH = "~/.config/ospd-logging.conf"
DEFAULT_UNIX_SOCKET_PATH = "/run/ospd/ospd-openvas.sock"
DEFAULT_PID_PATH = "/run/ospd/ospd.pid"
DEFAULT_LOCKFILE_DIR_PATH = "/run/ospd"
DEFAULT_STREAM_TIMEOUT = 10  # ten seconds
DEFAULT_SCANINFO_STORE_TIME = 0  # in hours
DEFAULT_MAX_SCAN = 0  # 0 = disable
DEFAULT_MIN_FREE_MEM_SCAN_QUEUE = 0  # 0 = Disable
DEFAULT_MAX_QUEUED_SCANS = 0  # 0 = Disable
DEFAULT_MQTT_BROKER_ADDRESS = "localhost"
DEFAULT_MQTT_BROKER_PORT = 1883

ParserType = argparse.ArgumentParser
Arguments = argparse.Namespace

logger = logging.getLogger(__name__)


class CliParser:
    def __init__(self, description: str) -> None:
        """Create a command-line arguments parser for OSPD."""
        self._name = description
        parser = argparse.ArgumentParser(description=description)

        parser.add_argument(
            '--version', action='store_true', help='Print version then exit.'
        )

        parser.add_argument(
            '-s',
            '--config',
            nargs='?',
            help=f'Configuration file path (default: {DEFAULT_CONFIG_PATH})',
        )
        parser.add_argument(
            '--log-config',
            nargs='?',
            default=DEFAULT_LOG_CONFIG_PATH,
            help='Log configuration file path (default: %(default)s)',
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
            help=(
                'Location of the file for the process ID. Default: %(default)s'
            ),
        )
        parser.add_argument(
            '--lock-file-dir',
            default=DEFAULT_LOCKFILE_DIR_PATH,
            help='Directory where lock files are placed. Default: %(default)s',
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
            default='INFO',
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
        parser.add_argument(
            '--scaninfo-store-time',
            default=DEFAULT_SCANINFO_STORE_TIME,
            type=int,
            help=(
                'Time in hours a scan is stored before being considered '
                'forgotten and being delete from the scan table. '
                'Default %(default)s, disabled.'
            ),
        )
        parser.add_argument(
            '--list-commands',
            action='store_true',
            help='Display all protocol commands',
        )
        parser.add_argument(
            '--max-scans',
            default=DEFAULT_MAX_SCAN,
            type=int,
            help=(
                'Max. amount of parallel task that can be started. '
                'Default %(default)s, disabled'
            ),
        )
        parser.add_argument(
            '--min-free-mem-scan-queue',
            default=DEFAULT_MIN_FREE_MEM_SCAN_QUEUE,
            type=int,
            help=(
                'Minimum free memory in MB required to run the scan. '
                'If no enough free memory is available, the scan queued. '
                'Default %(default)s, disabled'
            ),
        )
        parser.add_argument(
            '--max-queued-scans',
            default=DEFAULT_MAX_QUEUED_SCANS,
            type=int,
            help=(
                'Maximum number allowed of queued scans before '
                'starting to reject new scans. '
                'Default %(default)s, disabled'
            ),
        )
        parser.add_argument(
            '--mqtt-broker-address',
            default=DEFAULT_MQTT_BROKER_ADDRESS,
            type=str,
            help=(
                'Broker address to connect to for MQTT communication.'
                ' Neccessary to get results from Notus-Scanner.Default'
                ' %(default)s'
            ),
        )
        parser.add_argument(
            '--mqtt-broker-port',
            default=DEFAULT_MQTT_BROKER_PORT,
            type=self.network_port,
            help=(
                'Broker port to connect to for MQTT communication.'
                ' Neccessary to get results from Notus-Scanner.Default'
                'Default %(default)s'
            ),
        )
        parser.add_argument(
            '--feed-updater',
            default="openvas",
            choices=['openvas', 'nasl-cli'],
            help=(
                'Sets the method of updating the feed.'
                ' Can either be openvas or nasl-cli.'
                ' Default: %(default)s.'
            ),
        )

        self.parser = parser

    def network_port(self, string: str) -> int:
        """Check if provided string is a valid network port."""

        value = int(string)
        if not 0 < value <= 65535:
            raise argparse.ArgumentTypeError(
                'port must be in ]0,65535] interval'
            )
        return value

    def log_level(self, string: str) -> str:
        """Check if provided string is a valid log level."""

        if not hasattr(logging, string.upper()):
            raise argparse.ArgumentTypeError(
                'log level must be one of {debug,info,warning,error,critical}'
            )
        return string.upper()

    def _set_defaults(self, configfilename=None) -> None:
        self._config = self._load_config(configfilename)
        self.parser.set_defaults(**self._config.defaults())

    def _load_config(self, configfile: str) -> Config:
        config = Config()

        configpath = Path(configfile or DEFAULT_CONFIG_PATH)

        if not configpath.expanduser().resolve().exists():
            if configfile:
                # user has passed an config file
                # print error and exit
                self.parser.error(f'Config file {configpath} does not exist')
            else:
                logger.debug('Ignoring non existing config file %s', configfile)
                return config

        try:
            config.load(configpath, def_section=self._name)
            logger.debug('Loaded config %s', configfile)
        except Exception as e:  # pylint: disable=broad-except
            raise RuntimeError(
                f'Error while parsing config file {configfile}. Error was {e}'
            ) from None

        return config

    def parse_arguments(self, args=None):
        # Parse args to get the config file path passed as option
        _args, _ = self.parser.parse_known_args(args)

        # Load the defaults from the config file if it exists.
        # This override also what it was passed as cmd option.
        self._set_defaults(_args.config)
        args, _ = self.parser.parse_known_args(args)

        return args


def create_parser(description: str) -> CliParser:
    return CliParser(description)
