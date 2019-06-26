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

from typing import Type, Optional

from ospd.misc import go_to_background
from ospd.ospd import OSPDaemon
from ospd.parser import create_args_parser, ParserType
from ospd.server import TlsServer, UnixSocketServer


def print_version(wrapper, file=sys.stdout):
    """ Prints the server version and license information."""

    scanner_name = wrapper.get_scanner_name()
    server_version = wrapper.get_server_version()
    protocol_version = wrapper.get_protocol_version()
    daemon_name = wrapper.get_daemon_name()
    daemon_version = wrapper.get_daemon_version()

    file.write(
        "OSP Server for {0} version {1}".format(scanner_name, server_version)
    )
    file.write("OSP Version: {0}".format(protocol_version))
    file.write("Using: {0} {1}".format(daemon_name, daemon_version))
    file.write(
        "Copyright (C) 2014, 2015 Greenbone Networks GmbH\n"
        "License GPLv2+: GNU GPL version 2 or later\n"
        "This is free software: you are free to change"
        " and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law."
    )


def init_logging(
    name: str,
    log_level: int,
    *,
    log_file: Optional[str] = None,
    foreground: Optional[bool] = False,
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
    name: str, klass: Type[OSPDaemon], parser: Optional[ParserType] = None
):
    """ OSPD Main function. """

    if not parser:
        parser = create_args_parser(name)

    args = parser.parse_args()

    init_logging(
        name, args.log_level, log_file=args.log_file, foreground=args.foreground
    )

    if args.unix_socket:
        server = UnixSocketServer(args.unix_socket)
    else:
        server = TlsServer(
            args.address, args.port, args.cert_file, args.key_file, args.ca_file
        )

    wrapper = klass(**vars(args))

    if args.version:
        print_version(wrapper)
        sys.exit()

    if not args.foreground:
        go_to_background()

    if not wrapper.check():
        return 1

    wrapper.run(server)

    return 0
