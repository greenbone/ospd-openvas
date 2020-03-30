# Copyright (C) 2014-2020 Greenbone Networks GmbH
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

# pylint: disable=too-many-lines

""" Miscellaneous classes and functions related to OSPD.
"""

import logging
import os
import sys
import uuid
import multiprocessing

from typing import Any, Callable, Iterable
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def create_process(
    func: Callable, *, args: Iterable[Any] = None
) -> multiprocessing.Process:
    return multiprocessing.Process(target=func, args=args)


class ResultType(object):

    """ Various scan results types values. """

    ALARM = 0
    LOG = 1
    ERROR = 2
    HOST_DETAIL = 3

    @classmethod
    def get_str(cls, result_type: int) -> str:
        """ Return string name of a result type. """
        if result_type == cls.ALARM:
            return "Alarm"
        elif result_type == cls.LOG:
            return "Log Message"
        elif result_type == cls.ERROR:
            return "Error Message"
        elif result_type == cls.HOST_DETAIL:
            return "Host Detail"
        else:
            assert False, "Erroneous result type {0}.".format(result_type)

    @classmethod
    def get_type(cls, result_name: str) -> int:
        """ Return string name of a result type. """
        if result_name == "Alarm":
            return cls.ALARM
        elif result_name == "Log Message":
            return cls.LOG
        elif result_name == "Error Message":
            return cls.ERROR
        elif result_name == "Host Detail":
            return cls.HOST_DETAIL
        else:
            assert False, "Erroneous result name {0}.".format(result_name)


def valid_uuid(value) -> bool:
    """ Check if value is a valid UUID. """

    try:
        uuid.UUID(value, version=4)
        return True
    except (TypeError, ValueError, AttributeError):
        return False


def go_to_background() -> None:
    """ Daemonize the running process. """
    try:
        if os.fork():
            sys.exit()
    except OSError as errmsg:
        LOGGER.error('Fork failed: %s', errmsg)
        sys.exit(1)


def create_pid(pidfile: str) -> bool:
    """ Check if there is an already running daemon and creates the pid file.
    Otherwise gives an error. """

    pid = str(os.getpid())
    pidpath = Path(pidfile)

    if pidpath.is_file():
        LOGGER.error("There is an already running process.")
        return False

    try:
        with pidpath.open(mode='w') as f:
            f.write(pid)
    except (FileNotFoundError, PermissionError) as e:
        LOGGER.error(
            "Failed to create pid file %s. %s", str(pidpath.absolute()), e
        )
        return False

    return True
