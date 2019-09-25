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

import logging

from logging.handlers import SysLogHandler, WatchedFileHandler

import os
import sys
import atexit
import signal

from functools import partial

from typing import Type, Optional

from ospd.misc import go_to_background, create_pid, remove_pidfile
from ospd.ospd import OSPDaemon
from ospd.parser import create_parser, ParserType
from ospd.server import TlsServer, UnixSocketServer

COPYRIGHT = """Copyright (C) 2014, 2015, 2018, 2019 Greenbone Networks GmbH
License GPLv2+: GNU GPL version 2 or later
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law."""


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


def init_logging(
    name: str,
    log_level: int,
    *,
    log_file: Optional[str] = None,
    foreground: Optional[bool] = False
):

    rootlogger = logging.getLogger()
    rootlogger.setLevel(log_level)

    if foreground:
        console = logging.StreamHandler()
        console.setFormatter(
            logging.Formatter(
                '%(asctime)s {}: %(levelname)s: (%(name)s) %(message)s'.format(
                    name
                )
            )
        )
        rootlogger.addHandler(console)
    elif log_file:
        logfile = WatchedFileHandler(log_file)
        logfile.setFormatter(
            logging.Formatter(
                '%(asctime)s {}: %(levelname)s: (%(name)s) %(message)s'.format(
                    name
                )
            )
        )
        rootlogger.addHandler(logfile)
    else:
        syslog = SysLogHandler('/dev/log')
        syslog.setFormatter(
            logging.Formatter(
                '{}: %(levelname)s: (%(name)s) %(message)s'.format(name)
            )
        )
        rootlogger.addHandler(syslog)
        # Duplicate syslog's file descriptor to stout/stderr.
        syslog_fd = syslog.socket.fileno()
        os.dup2(syslog_fd, 1)
        os.dup2(syslog_fd, 2)


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
        name, args.log_level, log_file=args.log_file, foreground=args.foreground
    )

    if args.port == 0:
        server = UnixSocketServer(
            args.unix_socket,
            args.socket_mode,
            args.stream_timeout,
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

    if not args.foreground:
        go_to_background()

    if not create_pid(args.pid_file):
        sys.exit()

    # Set signal handler and cleanup
    atexit.register(remove_pidfile, pidfile=args.pid_file)
    signal.signal(
        signal.SIGTERM, partial(remove_pidfile, args.pid_file)
    )

    daemon.init()

    if not daemon.check():
        return 1

    daemon.run(server)

    return 0
