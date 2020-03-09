# -*- coding: utf-8 -*-
# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

import logging
import time

from pathlib import Path

logger = logging.getLogger(__name__)


class LockFile:
    def __init__(self, path: Path):
        self._lock_file_path = path
        self._has_lock = False

    def is_locked(self) -> bool:
        return self._lock_file_path.exists()

    def has_lock(self) -> bool:
        return self._has_lock

    def acquire_lock(self) -> "LockFile":
        """ Acquite a lock by creating a lock file.
        """
        if self.has_lock() or self.is_locked():
            return self

        try:
            # create parent directories recursively
            parent_dir = self._lock_file_path.parent
            parent_dir.mkdir(parents=True, exist_ok=True)

            self._lock_file_path.touch(exist_ok=False)
            self._has_lock = True

            logger.debug("Created lock file %s.", str(self._lock_file_path))

        except FileExistsError as e:
            logger.error(
                "Failed to create lock file %s. %s",
                str(self._lock_file_path),
                e,
            )

        return self

    def wait_for_lock(self):
        while not self.has_lock():
            self.acquire_lock()
            time.sleep(10)

        return self

    def release_lock(self) -> None:
        """ Release the lock by deleting the lock file
        """
        if self.has_lock() and self.is_locked():
            self._lock_file_path.unlink()
            self._has_lock = False
            logger.debug("Removed lock file %s.", str(self._lock_file_path))

    def __enter__(self):
        self.acquire_lock()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.release_lock()
