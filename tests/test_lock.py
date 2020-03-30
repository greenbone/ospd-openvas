# -*- coding: utf-8 -*-
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

import unittest
import shutil
import tempfile

from pathlib import Path

from ospd_openvas.lock import LockFile


class LockFileTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(str(self.temp_dir))

    def test_is_locked(self):
        lock_file_path = self.temp_dir / 'test.lock'

        lock_file = LockFile(lock_file_path)

        self.assertFalse(lock_file.is_locked())

        lock_file_path.touch()

        self.assertTrue(lock_file.is_locked())

    def test_acquire_lock(self):
        lock_file_path = self.temp_dir / 'test.lock'

        lock_file = LockFile(lock_file_path)
        lock_file.acquire_lock()

        self.assertTrue(lock_file.has_lock())
        self.assertTrue(lock_file.is_locked())

        self.assertTrue(lock_file_path.exists())

    def test_already_locked(self):
        lock_file_path = self.temp_dir / 'test.lock'
        lock_file_path.touch()

        lock_file = LockFile(lock_file_path)
        lock_file.acquire_lock()

        self.assertFalse(lock_file.has_lock())
        self.assertTrue(lock_file.is_locked())

        self.assertTrue(lock_file_path.exists())

    def test_create_parent_dirs(self):
        lock_file_path = self.temp_dir / 'foo' / 'bar' / 'test.lock'

        lock_file = LockFile(lock_file_path)
        lock_file.acquire_lock()

        self.assertTrue(lock_file.has_lock())
        self.assertTrue(lock_file.is_locked())

        self.assertTrue(lock_file_path.exists())
        self.assertTrue(lock_file_path.parent.is_dir())
        self.assertTrue(lock_file_path.parent.parent.is_dir())

    def test_context_manager(self):
        lock_file_path = self.temp_dir / 'test.lock'

        lock_file = LockFile(lock_file_path)

        with lock_file:
            self.assertTrue(lock_file.is_locked())
            self.assertTrue(lock_file.has_lock())
            self.assertTrue(lock_file_path.is_file())

        self.assertFalse(lock_file.is_locked())
        self.assertFalse(lock_file.has_lock())
        self.assertFalse(lock_file_path.is_file())

    def test_context_manager_lock_exists(self):
        lock_file_path = self.temp_dir / 'test.lock'
        lock_file_path.touch()

        lock_file = LockFile(lock_file_path)

        with lock_file:
            self.assertTrue(lock_file.is_locked())
            self.assertTrue(lock_file_path.is_file())
            self.assertFalse(lock_file.has_lock())

        self.assertTrue(lock_file.is_locked())
        self.assertFalse(lock_file.has_lock())
        self.assertTrue(lock_file_path.is_file())
