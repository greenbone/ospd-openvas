# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import time
import logging

from ospd.errors import OspdError


logger = logging.getLogger(__name__)


class TimerError(OspdError):
    """Timer errors"""


class Timer:
    def __init__(
        self,
        name: str = None,
        text: str = "{}: Elapsed time: {:0.4f} seconds",
        logger=logger.debug,  # pylint: disable=redefined-outer-name
    ):
        self._start_time = None
        self._name = name
        self._text = text
        self._logger = logger

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.stop()

    @staticmethod
    def create(name) -> "Timer":
        timer = Timer(name)
        timer.start()
        return timer

    def start(self):
        """Start a new timer"""
        self._start_time = time.perf_counter()

    def stop(self):
        if not self._start_time:
            raise TimerError('Timer is not running.')

        duration = time.perf_counter() - self._start_time

        if self._logger:
            self._logger(self._text.format(self._name, duration))

        return duration
