# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# pylint: disable=too-many-lines

"""Miscellaneous classes and functions related to OSPD."""

import logging
import os
import sys
import uuid
import multiprocessing

from typing import Any, Callable, Iterable
from pathlib import Path

import psutil

logger = logging.getLogger(__name__)


def create_process(
    func: Callable, *, args: Iterable[Any] = None
) -> multiprocessing.Process:
    return multiprocessing.Process(target=func, args=args)


class ResultType(object):
    """Various scan results types values."""

    ALARM = 0
    LOG = 1
    ERROR = 2
    HOST_DETAIL = 3

    @classmethod
    def get_str(cls, result_type: int) -> str:
        """Return string name of a result type."""
        if result_type == cls.ALARM:
            return "Alarm"
        elif result_type == cls.LOG:
            return "Log Message"
        elif result_type == cls.ERROR:
            return "Error Message"
        elif result_type == cls.HOST_DETAIL:
            return "Host Detail"
        else:
            assert False, f"Erroneous result type {result_type}."

    @classmethod
    def get_type(cls, result_name: str) -> int:
        """Return string name of a result type."""
        if result_name == "Alarm":
            return cls.ALARM
        elif result_name == "Log Message":
            return cls.LOG
        elif result_name == "Error Message":
            return cls.ERROR
        elif result_name == "Host Detail":
            return cls.HOST_DETAIL
        else:
            assert False, f"Erroneous result name {result_name}."


def valid_uuid(value) -> bool:
    """Check if value is a valid UUID."""

    try:
        uuid.UUID(value, version=4)
        return True
    except (TypeError, ValueError, AttributeError):
        return False


def go_to_background() -> None:
    """Daemonize the running process."""
    try:
        if os.fork():
            sys.exit()
    except OSError as errmsg:
        logger.error('Fork failed: %s', errmsg)
        sys.exit(1)


def create_pid(pidfile: str) -> bool:
    """Check if there is an already running daemon and creates the pid file.
    Otherwise gives an error."""

    pid = os.getpid()
    current_process = psutil.Process(pid)
    current_process_name = current_process.name()

    pidpath = Path(pidfile)
    pf_process_name = ""
    pf_pid = ""

    if pidpath.is_file():
        with pidpath.open('r', encoding='utf-8') as file:
            pf_pid = file.read().strip()
            try:
                pf_pid = int(pf_pid)
            except (TypeError, ValueError):
                pf_pid = None

        if pf_pid:
            try:
                process = psutil.Process(pf_pid)
                pf_process_name = process.name()
            except psutil.NoSuchProcess:
                pass

            if pf_process_name == current_process_name and pf_pid != pid:
                logger.error(
                    "There is an already running process. See %s.",
                    str(pidpath.absolute()),
                )
                return False
            else:
                logger.debug(
                    "There is an existing pid file '%s', but the PID %s "
                    "belongs to the process %s. It seems that %s was "
                    "abruptly stopped. Removing the pid file.",
                    str(pidpath.absolute()),
                    pf_pid,
                    pf_process_name,
                    current_process_name,
                )

    try:
        with pidpath.open(mode='w', encoding='utf-8') as f:
            f.write(str(pid))
    except (FileNotFoundError, PermissionError) as e:
        logger.error(
            "Failed to create pid file %s. %s", str(pidpath.absolute()), e
        )
        return False

    return True
