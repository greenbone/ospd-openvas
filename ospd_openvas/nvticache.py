# -*- coding: utf-8 -*-
# Copyright (C) 2014-2021 Greenbone AG
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


""" Provide functions to handle NVT Info Cache. """

import logging

from typing import List, Dict, Optional, Iterator, Tuple
from pathlib import Path
from time import time

from ospd.errors import RequiredArgument
from ospd_openvas.errors import OspdOpenvasError
from ospd_openvas.db import NVT_META_FIELDS, OpenvasDB, MainDB, BaseDB, RedisCtx

NVTI_CACHE_NAME = "nvticache"

logger = logging.getLogger(__name__)

LIST_FIRST_POS = 0
LIST_LAST_POS = -1


class NVTICache(BaseDB):
    QOD_TYPES = {
        'exploit': '100',
        'remote_vul': '99',
        'remote_app': '98',
        'package': '97',
        'registry': '97',
        'remote_active': '95',
        'remote_banner': '80',
        'executable_version': '80',
        'remote_analysis': '70',
        'remote_probe': '50',
        'package_unreliable': '30',
        'remote_banner_unreliable': '30',
        'executable_version_unreliable': '30',
        'general_note': '1',
        'default': '70',
    }

    def __init__(  # pylint: disable=super-init-not-called
        self, main_db: MainDB
    ):
        self._ctx = None
        self.index = None
        self._main_db = main_db

    @property
    def ctx(self) -> Optional[RedisCtx]:
        if self._ctx is None:
            self._ctx, self.index = OpenvasDB.find_database_by_pattern(
                NVTI_CACHE_NAME, self._main_db.max_database_index
            )
        return self._ctx

    def get_feed_version(self) -> Optional[str]:
        """Get feed version of the nvti cache db.

        Returns the feed version or None if the nvt feed isn't available.
        """
        if not self.ctx:
            # no nvti cache db available yet
            return None

        # no feed version for notus otherwise tha would be a contract change
        return OpenvasDB.get_single_item(self.ctx, NVTI_CACHE_NAME)

    def get_oids(self) -> Iterator[Tuple[str, str]]:
        """Get the list of NVT file names and OIDs.

        Returns:
            An iterable of tuples of file name and oid.
        """

        def parse_oid(item):
            return item[4:]

        if self.ctx:
            for f, oid in OpenvasDB.get_filenames_and_oids(
                self.ctx, 'nvt:*', parse_oid
            ):
                yield (f, oid)

    def get_nvt_params(self, oid: str) -> Optional[Dict[str, str]]:
        """Get NVT's preferences.

        Arguments:
            oid: OID of VT from which to get the parameters.

        Returns:
            A dictionary with preferences and timeout.
        """
        prefs = self.get_nvt_prefs(oid)

        vt_params = {}

        if prefs:
            for nvt_pref in prefs:
                elem = nvt_pref.split('|||')

                param_id = elem[0]
                param_name = elem[1]
                param_type = elem[2]

                vt_params[param_id] = dict()
                vt_params[param_id]['id'] = param_id
                vt_params[param_id]['type'] = param_type
                vt_params[param_id]['name'] = param_name.strip()
                vt_params[param_id]['description'] = 'Description'

                if len(elem) > 3:
                    param_default = elem[3]
                    vt_params[param_id]['default'] = param_default
                else:
                    vt_params[param_id]['default'] = ''

        return vt_params

    @staticmethod
    def _parse_metadata_tags(tags_str: str, oid: str) -> Dict[str, str]:
        """Parse a string with multiple tags.

        Arguments:
            tags_str: String with tags separated by `|`.
            oid: VT OID. Only used for logging in error case.

        Returns:
            A dictionary with the tags.
        """
        tags_dict = dict()
        tags = tags_str.split('|')
        for tag in tags:
            try:
                _tag, _value = tag.split('=', 1)
            except ValueError:
                logger.error('Tag %s in %s has no value.', tag, oid)
                continue
            tags_dict[_tag] = _value

        return tags_dict

    def get_nvt_metadata(self, oid: str) -> Optional[Dict[str, str]]:
        """Get a full NVT. Returns an XML tree with the NVT metadata.

        Arguments:
            oid: OID of VT from which to get the metadata.

        Returns:
            A dictionary with the VT metadata.
        """
        resp = OpenvasDB.get_list_item(
            self.ctx,
            f"nvt:{oid}",
            start=NVT_META_FIELDS.index("NVT_FILENAME_POS"),
            end=NVT_META_FIELDS.index("NVT_NAME_POS"),
        )

        if not isinstance(resp, list) or len(resp) == 0:
            return None

        subelem = [
            'filename',
            'required_keys',
            'mandatory_keys',
            'excluded_keys',
            'required_udp_ports',
            'required_ports',
            'dependencies',
            'tag',
            'cve',
            'bid',
            'xref',
            'category',
            'family',
            'name',
        ]

        custom = dict()
        custom['refs'] = dict()
        for child, res in zip(subelem, resp):
            if child not in ['cve', 'bid', 'xref', 'tag'] and res:
                custom[child] = res
            elif child == 'tag':
                custom.update(self._parse_metadata_tags(res, oid))
            elif child in ['cve', 'bid', 'xref'] and res:
                custom['refs'][child] = res.split(", ")

        custom['vt_params'] = dict()
        custom['vt_params'].update(self.get_nvt_params(oid))

        return custom

    def get_nvt_refs(self, oid: str) -> Optional[Dict[str, str]]:
        """Get a full NVT.

        Arguments:
            oid: OID of VT from which to get the VT references.

        Returns:
            A dictionary with the VT references.
        """
        resp = OpenvasDB.get_list_item(
            self.ctx,
            f"nvt:{oid}",
            start=NVT_META_FIELDS.index("NVT_CVES_POS"),
            end=NVT_META_FIELDS.index("NVT_XREFS_POS"),
        )

        if not isinstance(resp, list) or len(resp) == 0:
            return None

        subelem = ['cve', 'bid', 'xref']

        refs = dict()
        for child, res in zip(subelem, resp):
            refs[child] = res.split(", ")

        return refs

    def get_nvt_family(self, oid: str) -> Optional[str]:
        """Get NVT family
        Arguments:
            oid: OID of VT from which to get the VT family.

        Returns:
            A str with the VT family.
        """
        return OpenvasDB.get_single_item(
            self.ctx,
            f"nvt:{oid}",
            index=NVT_META_FIELDS.index("NVT_FAMILY_POS"),
        )

    def get_nvt_prefs(self, oid: str) -> Optional[List[str]]:
        """Get NVT preferences.

        Arguments:
            ctx: Redis context to be used.
            oid: OID of VT from which to get the VT preferences.

        Returns:
            A list with the VT preferences.
        """
        key = f'oid:{oid}:prefs'
        # notus doesn't seem to have preferences, ignoring
        return OpenvasDB.get_list_item(self.ctx, key)

    def get_nvt_tags(self, oid: str) -> Optional[Dict[str, str]]:
        """Get Tags of the given OID.

        Arguments:
            ctx: Redis context to be used.
            oid: OID of VT from which to get the VT tags.

        Returns:
            A dictionary with the VT tags.
        """
        tag = OpenvasDB.get_single_item(
            self.ctx,
            f"nvt:{oid}",
            index=NVT_META_FIELDS.index('NVT_TAGS_POS'),
        )
        tags = tag.split('|')

        return dict([item.split('=', 1) for item in tags])

    def get_nvt_files_count(self) -> int:
        return OpenvasDB.get_key_count(self.ctx, "filename:*")

    def get_nvt_count(self) -> int:
        return OpenvasDB.get_key_count(self.ctx, "nvt:*")

    def add_vt_to_cache(self, vt_id: str, vt: List[str]):
        if not vt_id:
            raise RequiredArgument('add_vt_to_cache', 'vt_id')
        if not vt:
            raise RequiredArgument('add_vt_to_cache', 'vt')
        if not isinstance(vt, list) or len(vt) != 15:
            raise OspdOpenvasError(f'Error trying to load the VT {vt} in cache')

        OpenvasDB.add_single_list(self.ctx, vt_id, vt)

        OpenvasDB.add_single_item(self.ctx, f'filename:{vt[0]}', [int(time())])

    def get_file_checksum(self, file_abs_path: Path) -> str:
        """Get file sha256 checksum or md5 checksum

        Arguments:
            file_abs_path: File to get the checksum

        Returns:
            The checksum
        """
        # Try to get first sha256 checksum
        sha256sum = OpenvasDB.get_single_item(
            self.ctx,
            f'sha256sums:{file_abs_path}',
        )
        if sha256sum:
            return sha256sum

        # Search for md5 checksum
        md5sum = OpenvasDB.get_single_item(
            self.ctx,
            f'md5sums:{file_abs_path}',
        )
        if md5sum:
            return md5sum
