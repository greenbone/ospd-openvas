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

import time
import logging

from ospd.errors import OspdError


logger = logging.getLogger(__name__)


class TimerError(OspdError):
    """ Timer errors """


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
