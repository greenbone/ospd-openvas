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

""" Pikle Handler class
"""

import logging
import pickle

from pathlib import Path
from ospd.errors import OspdCommandError

logger = logging.getLogger(__name__)


class DataPickler:
    def __init__(self, storage_path):
        self._storage_path = storage_path

    def remove_file(self, filename):
        """ Remove the file containing a scan_info pickled object """
        storage_file_path = Path(self._storage_path) / filename
        storage_file_path.unlink()

    def store_data(self, filename, data_object):
        """ Pickle a object and store it in a file named"""
        storage_file_path = Path(self._storage_path) / filename

        try:
            # create parent directories recursively
            parent_dir = storage_file_path.parent
            parent_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:  # pylint: disable=broad-except
            raise OspdCommandError(
                'Not possible to store scan info for %s. %s' % (filename, e),
                'start_scan',
            )

        try:
            with storage_file_path.open('wb') as scan_info_f:
                pickle.dump(data_object, scan_info_f)
        except Exception as e:
            raise OspdCommandError(
                'Not possible to store scan info for %s. %s' % (filename, e),
                'start_scan',
            )

    def load_data(self, filename):
        """ Unpikle stored data """

        storage_file_path = Path(self._storage_path) / filename
        unpikled_scan_info = None
        try:
            with storage_file_path.open('rb') as scan_info_f:
                unpikled_scan_info = pickle.load(scan_info_f)
        except Exception as e:
            logger.error('Not possible to load data from %s. %s', filename, e)

        return unpikled_scan_info
