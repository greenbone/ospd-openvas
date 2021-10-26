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

import pickle

from pathlib import Path
from hashlib import sha256
from unittest import TestCase
from unittest.mock import patch

from ospd.errors import OspdCommandError
from ospd.datapickler import DataPickler

from .helper import assert_called


class DataPecklerTestCase(TestCase):
    def test_store_data(self):
        data = {'foo', 'bar'}
        filename = 'scan_info_1'
        pickled_data = pickle.dumps(data)
        tmp_hash = sha256()
        tmp_hash.update(pickled_data)

        data_pickler = DataPickler('/tmp')
        ret = data_pickler.store_data(filename, data)

        self.assertEqual(ret, tmp_hash.hexdigest())

        data_pickler.remove_file(filename)

    def test_store_data_failed(self):
        data = {'foo', 'bar'}
        filename = 'scan_info_1'

        data_pickler = DataPickler('/root')

        self.assertRaises(
            OspdCommandError, data_pickler.store_data, filename, data
        )

    def test_store_data_check_permission(self):
        OWNER_ONLY_RW_PERMISSION = '0o100600'  # pylint: disable=invalid-name
        data = {'foo', 'bar'}
        filename = 'scan_info_1'

        data_pickler = DataPickler('/tmp')
        data_pickler.store_data(filename, data)

        file_path = (
            Path(data_pickler._storage_path)  # pylint: disable=protected-access
            / filename
        )
        self.assertEqual(
            oct(file_path.stat().st_mode), OWNER_ONLY_RW_PERMISSION
        )

        data_pickler.remove_file(filename)

    def test_load_data(self):

        data_pickler = DataPickler('/tmp')

        data = {'foo', 'bar'}
        filename = 'scan_info_1'
        pickled_data = pickle.dumps(data)

        tmp_hash = sha256()
        tmp_hash.update(pickled_data)
        pickled_data_hash = tmp_hash.hexdigest()

        ret = data_pickler.store_data(filename, data)
        self.assertEqual(ret, pickled_data_hash)

        original_data = data_pickler.load_data(filename, pickled_data_hash)
        self.assertIsNotNone(original_data)

        self.assertIn('foo', original_data)

    @patch("ospd.datapickler.logger")
    def test_remove_file_failed(self, mock_logger):
        filename = 'inenxistent_file'
        data_pickler = DataPickler('/root')
        data_pickler.remove_file(filename)

        assert_called(mock_logger.error)

    @patch("ospd.datapickler.logger")
    def test_load_data_no_file(self, mock_logger):
        filename = 'scan_info_1'
        data_pickler = DataPickler('/tmp')

        data_loaded = data_pickler.load_data(filename, "1234")
        assert_called(mock_logger.error)
        self.assertIsNone(data_loaded)

        data_pickler.remove_file(filename)

    def test_load_data_corrupted(self):

        data_pickler = DataPickler('/tmp')

        data = {'foo', 'bar'}
        filename = 'scan_info_1'
        pickled_data = pickle.dumps(data)

        tmp_hash = sha256()
        tmp_hash.update(pickled_data)
        pickled_data_hash = tmp_hash.hexdigest()

        ret = data_pickler.store_data(filename, data)
        self.assertEqual(ret, pickled_data_hash)

        # courrupt data
        file_to_corrupt = (
            Path(data_pickler._storage_path)  # pylint: disable=protected-access
            / filename
        )
        with file_to_corrupt.open('ab') as f:
            f.write(b'bar2')

        original_data = data_pickler.load_data(filename, pickled_data_hash)
        self.assertIsNone(original_data)

        data_pickler.remove_file(filename)
