# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest
import shutil
import tempfile

from pathlib import Path, PosixPath

from unittest.mock import patch, MagicMock
from ospd_openvas.lock import LockFile
from .helper import assert_called_once, assert_called


class LockFileTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(str(self.temp_dir))

    def test_acquire_lock(self):
        lock_file_path = self.temp_dir / "test.lock"

        lock_file = LockFile(lock_file_path)
        lock_file._acquire_lock()  # pylint: disable = protected-access

        self.assertTrue(lock_file.has_lock())
        self.assertTrue(lock_file_path.exists())
        lock_file._release_lock()  # pylint: disable = protected-access

    @patch("ospd_openvas.lock.logger")
    def test_already_locked(self, mock_logger):
        lock_file_path = self.temp_dir / "test.lock"

        lock_file_aux = LockFile(lock_file_path)
        lock_file_aux._acquire_lock()  # pylint: disable = protected-access
        self.assertTrue(lock_file_aux.has_lock())

        lock_file = LockFile(lock_file_path)
        lock_file._acquire_lock()  # pylint: disable = protected-access
        self.assertFalse(lock_file.has_lock())
        assert_called(mock_logger.debug)

        lock_file_aux._release_lock()  # pylint: disable = protected-access

    def test_create_parent_dirs(self):
        lock_file_path = self.temp_dir / "foo" / "bar" / "test.lock"

        lock_file = LockFile(lock_file_path)
        lock_file._acquire_lock()  # pylint: disable = protected-access

        self.assertTrue(lock_file.has_lock())

        self.assertTrue(lock_file_path.exists())
        self.assertTrue(lock_file_path.parent.is_dir())
        self.assertTrue(lock_file_path.parent.parent.is_dir())

        lock_file._release_lock()  # pylint: disable = protected-access

    @patch("ospd_openvas.lock.logger")
    def test_create_paren_dirs_fail(self, mock_logger):
        lock_file_path = MagicMock(spec=Path).return_value
        parent = MagicMock(spec=PosixPath)
        lock_file_path.parent = parent
        parent.mkdir.side_effect = PermissionError

        lock_file = LockFile(lock_file_path)

        lock_file._acquire_lock()  # pylint: disable = protected-access
        self.assertFalse(lock_file.has_lock())

        assert_called_once(mock_logger.error)

    def test_context_manager(self):
        lock_file_path = self.temp_dir / "test.lock"

        lock_file = LockFile(lock_file_path)

        with lock_file:
            self.assertTrue(lock_file.has_lock())
            self.assertTrue(lock_file_path.is_file())
            lock_file._release_lock()  # pylint: disable = protected-access

        # The file is not removed
        self.assertFalse(lock_file.has_lock())
        self.assertTrue(lock_file_path.is_file())
