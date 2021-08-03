# Copyright (C) 2014-2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import logging

import os
import sys
import atexit
import signal

from functools import partial

from typing import Type, Optional
from pathlib import Path

from ospd.misc import go_to_background, create_pid
from ospd.ospd import OSPDaemon
from ospd.parser import create_parser, ParserType
from ospd.server import TlsServer, UnixSocketServer, BaseServer
from ospd.logger import init_logging


COPYRIGHT = """Copyright (C) 2014-2021 Greenbone Networks GmbH
License GPLv2+: GNU GPL version 2 or later
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law."""

LOGGER = logging.getLogger(__name__)


def print_version(daemon: OSPDaemon, file=sys.stdout):
    """ Prints the server version and license information."""

    scanner_name = daemon.get_scanner_name()
    server_version = daemon.get_server_version()
    protocol_version = daemon.get_protocol_version()
    daemon_name = daemon.get_daemon_name()
    daemon_version = daemon.get_daemon_version()

    print(
        "OSP Server for {0}: {1}".format(scanner_name, server_version),
        file=file,
    )
    print("OSP: {0}".format(protocol_version), file=file)
    print("{0}: {1}".format(daemon_name, daemon_version), file=file)
    print(file=file)
    print(COPYRIGHT, file=file)


def exit_cleanup(
    pidfile: str,
    server: BaseServer,
    daemon: OSPDaemon,
    _signum=None,
    _frame=None,
) -> None:
    """ Removes the pidfile before ending the daemon. """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    pidpath = Path(pidfile)

    if not pidpath.is_file():
        return

    with pidpath.open() as f:
        if int(f.read()) == os.getpid():
            LOGGER.debug("Performing exit clean up")
            daemon.daemon_exit_cleanup()
            LOGGER.info("Shutting-down server ...")
            server.close()
            LOGGER.debug("Finishing daemon process")
            pidpath.unlink()
            sys.exit()


def main(
    name: str,
    daemon_class: Type[OSPDaemon],
    parser: Optional[ParserType] = None,
):
    """ OSPD Main function. """

    if not parser:
        parser = create_parser(name)
    args = parser.parse_arguments()

    if args.version:
        args.foreground = True

    init_logging(
        args.log_level,
        log_file=args.log_file,
        log_config=args.log_config,
        foreground=args.foreground,
    )

    if args.port == 0:
        server = UnixSocketServer(
            args.unix_socket, args.socket_mode, args.stream_timeout
        )
    else:
        server = TlsServer(
            args.address,
            args.port,
            args.cert_file,
            args.key_file,
            args.ca_file,
            args.stream_timeout,
        )

    daemon = daemon_class(**vars(args))

    if args.version:
        print_version(daemon)
        sys.exit()

    if args.list_commands:
        print(daemon.get_help_text())
        sys.exit()

    if not args.foreground:
        go_to_background()

    if not create_pid(args.pid_file):
        sys.exit()

    # Set signal handler and cleanup
    atexit.register(
        exit_cleanup, pidfile=args.pid_file, server=server, daemon=daemon
    )
    signal.signal(
        signal.SIGTERM, partial(exit_cleanup, args.pid_file, server, daemon)
    )
    signal.signal(
        signal.SIGINT, partial(exit_cleanup, args.pid_file, server, daemon)
    )
    if not daemon.check():
        return 1

    LOGGER.info(
        "Starting %s version %s.",
        daemon.daemon_info['name'],
        daemon.daemon_info['version'],
    )

    daemon.init(server)
    daemon.run()

    return 0
