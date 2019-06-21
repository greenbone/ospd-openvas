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
import os
import sys

from ospd.misc import go_to_background
from ospd.parser import create_args_parser, get_common_args


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


def main(name, klass):
    """ OSPD Main function. """

    # Common args parser.
    parser = create_args_parser(name)

    # Common args
    cargs = get_common_args(parser)

    logging.getLogger().setLevel(cargs['log_level'])

    wrapper = klass(
        certfile=cargs['certfile'],
        keyfile=cargs['keyfile'],
        cafile=cargs['cafile'],
        niceness=cargs['niceness'],
    )

    if cargs['version']:
        print_version(wrapper)
        sys.exit()

    if cargs['foreground']:
        console = logging.StreamHandler()
        console.setFormatter(
            logging.Formatter(
                '%(asctime)s %(name)s: %(levelname)s: %(message)s'
            )
        )
        logging.getLogger().addHandler(console)
    elif cargs['log_file']:
        logfile = logging.handlers.WatchedFileHandler(cargs['log_file'])
        logfile.setFormatter(
            logging.Formatter(
                '%(asctime)s %(name)s: %(levelname)s: %(message)s'
            )
        )
        logging.getLogger().addHandler(logfile)
        go_to_background()
    else:
        syslog = logging.handlers.SysLogHandler('/dev/log')
        syslog.setFormatter(
            logging.Formatter('%(name)s: %(levelname)s: %(message)s')
        )
        logging.getLogger().addHandler(syslog)
        # Duplicate syslog's file descriptor to stout/stderr.
        syslog_fd = syslog.socket.fileno()
        os.dup2(syslog_fd, 1)
        os.dup2(syslog_fd, 2)
        go_to_background()

    if not wrapper.check():
        return 1

    return wrapper.run(cargs['address'], cargs['port'], cargs['unix_socket'])
