# -*- coding: utf-8 -*-
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
import time
import fcntl

from pathlib import Path

logger = logging.getLogger(__name__)


class LockFile:
    def __init__(self, path: Path):
        self._lock_file_path = path
        self._has_lock = False
        self._fd = None

    def has_lock(self) -> bool:
        return self._has_lock

    def _acquire_lock(self) -> "LockFile":
        """Acquire a lock by creating a lock file."""
        if self.has_lock():
            return self

        parent_dir = self._lock_file_path.parent

        try:
            # create parent directories recursively
            parent_dir.mkdir(parents=True, mode=0o770, exist_ok=True)
        except OSError as e:
            logger.error(
                "Could not create parent dir %s for lock file. %s",
                str(parent_dir),
                e,
            )
            return self

        try:
            # Open the fd with append flag to create the file
            # if not exists and to avoid deleting the content
            # something else wrote in it.
            self._fd = self._lock_file_path.open('a')
        except Exception as e:  # pylint: disable=broad-except
            logger.error(
                "Failed to open lock file %s. %s",
                str(self._lock_file_path),
                e,
            )
            try:
                self._fd.close()
                self._fd = None
            except Exception:  # pylint: disable=broad-except
                pass
            return self

        try:
            self._lock_file_path.chmod(0o660)
        except OSError as e:
            # ignore error because it is very likely that the file exists, has
            # the correct permissions but we are not the owner
            logger.debug(
                "Could not change permissions of lock file %s",
                str(self._lock_file_path),
            )

        # Try to acquire the lock.
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._has_lock = True
            logger.debug("Created lock file %s.", str(self._lock_file_path))
        except BlockingIOError as e:
            logger.debug(
                "Failed to lock the file %s. %s",
                str(self._lock_file_path),
                e,
            )
            try:
                self._fd.close()
                self._fd = None
            except Exception:  # pylint: disable=broad-except
                pass

        return self

    def wait_for_lock(self):
        while not self.has_lock():
            self._acquire_lock()
            time.sleep(10)

        return self

    def _release_lock(self) -> None:
        """Release the lock by deleting the lock file"""
        if self.has_lock() and self._fd:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._fd.close()
            self._fd = None
            self._has_lock = False
            logger.debug(
                "Removed lock from file %s.", str(self._lock_file_path)
            )

    def __enter__(self):
        self._acquire_lock()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self._release_lock()
