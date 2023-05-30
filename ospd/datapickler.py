# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

""" Pickle Handler class
"""

import logging
import pickle
import os

from hashlib import sha256
from pathlib import Path
from typing import BinaryIO, Any

from ospd.errors import OspdCommandError

logger = logging.getLogger(__name__)

OWNER_ONLY_RW_PERMISSION = 0o600


class DataPickler:
    def __init__(self, storage_path: str):
        self._storage_path = storage_path
        self._storage_fd = None

    def _fd_opener(self, path: str, flags: int) -> BinaryIO:
        os.umask(0)
        flags = os.O_CREAT | os.O_WRONLY
        self._storage_fd = os.open(path, flags, mode=OWNER_ONLY_RW_PERMISSION)
        return self._storage_fd

    def _fd_close(self) -> None:
        try:
            self._storage_fd.close()
            self._storage_fd = None
        except Exception:  # pylint: disable=broad-except
            pass

    def remove_file(self, filename: str) -> None:
        """Remove the file containing a scan_info pickled object"""
        storage_file_path = Path(self._storage_path) / filename
        try:
            storage_file_path.unlink()
        except Exception as e:  # pylint: disable=broad-except
            logger.error('Not possible to delete %s. %s', filename, e)

    def store_data(self, filename: str, data_object: Any) -> str:
        """Pickle a object and store it in a file named"""
        storage_file_path = Path(self._storage_path) / filename

        try:
            # create parent directories recursively
            parent_dir = storage_file_path.parent
            parent_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise OspdCommandError(
                f'Not possible to access dir for {filename}. {e}',
                'start_scan',
            ) from e

        try:
            pickled_data = pickle.dumps(data_object)
        except pickle.PicklingError as e:
            raise OspdCommandError(
                f'Not possible to pickle scan info for {filename}. {e}',
                'start_scan',
            ) from e

        try:
            with open(
                str(storage_file_path), 'wb', opener=self._fd_opener
            ) as scan_info_f:
                scan_info_f.write(pickled_data)
        except Exception as e:  # pylint: disable=broad-except
            self._fd_close()
            raise OspdCommandError(
                f'Not possible to store scan info for {filename}. {e}',
                'start_scan',
            ) from e
        self._fd_close()

        return self._pickled_data_hash_generator(pickled_data)

    def load_data(self, filename: str, original_data_hash: str) -> Any:
        """Unpickle the stored data in the filename. Perform an
        intengrity check of the read data with the the hash generated
        with the original data.

        Return:
            Dictionary containing the scan info. None otherwise.
        """

        storage_file_path = Path(self._storage_path) / filename
        pickled_data = None
        try:
            with storage_file_path.open('rb') as scan_info_f:
                pickled_data = scan_info_f.read()
        except Exception as e:  # pylint: disable=broad-except
            logger.error(
                'Not possible to read pickled data from %s. %s', filename, e
            )
            return

        unpickled_scan_info = None
        try:
            unpickled_scan_info = pickle.loads(pickled_data)
        except pickle.UnpicklingError as e:
            logger.error(
                'Not possible to read pickled data from %s. %s', filename, e
            )
            return

        pickled_scan_info_hash = self._pickled_data_hash_generator(pickled_data)

        if original_data_hash != pickled_scan_info_hash:
            logger.error('Unpickled data from %s corrupted.', filename)
            return

        return unpickled_scan_info

    def _pickled_data_hash_generator(self, pickled_data: bytes) -> str:
        """Calculate the sha256 hash of a pickled data"""
        if not pickled_data:
            return

        hash_sha256 = sha256()
        hash_sha256.update(pickled_data)

        return hash_sha256.hexdigest()
