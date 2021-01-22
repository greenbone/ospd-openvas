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


""" Provide functions to handle NVT Info Cache. """

import logging

from typing import List, Dict, Optional, Iterator, Tuple

from packaging.specifiers import SpecifierSet
from packaging.version import parse as parse_version

from ospd_openvas.db import NVT_META_FIELDS, OpenvasDB, MainDB, BaseDB, RedisCtx
from ospd_openvas.errors import OspdOpenvasError
from ospd_openvas.openvas import Openvas


logger = logging.getLogger(__name__)

LIST_FIRST_POS = 0
LIST_LAST_POS = -1

# actually the nvti cache with gvm-libs 10 should fit too but openvas was only
# introduced with GVM 11 and gvm-libs 11
SUPPORTED_NVTICACHE_VERSIONS_SPECIFIER = SpecifierSet('>=11.0')


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
        self._nvti_cache_name = None

    def _get_nvti_cache_name(self) -> str:
        if not self._nvti_cache_name:
            self._set_nvti_cache_name()

        return self._nvti_cache_name

    def _is_compatible_version(self, version: str) -> bool:
        installed_version = parse_version(version)
        return installed_version in SUPPORTED_NVTICACHE_VERSIONS_SPECIFIER

    def _set_nvti_cache_name(self):
        """Set nvticache name"""
        version_string = Openvas.get_gvm_libs_version()
        if not version_string:
            raise OspdOpenvasError(
                "Not possible to get the installed gvm-libs version. "
                "Outdated openvas version. openvas version needs to be at "
                "least 7.0.1."
            )
        # Remove pre-release sufix and git revision if exists
        # as the gvm-libs version has the format
        # e.g. "20.8+beta1~git-123-somefix" for beta version from sources
        # or "20.8.0~git-123-hotfix" for a stable version from sources (no beta)
        version_string = version_string.split("+")[0]
        version_string = version_string.split("~")[0]

        if self._is_compatible_version(version_string):
            self._nvti_cache_name = "nvticache{}".format(version_string)
        else:
            raise OspdOpenvasError(
                "Error setting nvticache. Incompatible nvticache "
                "version {}. Supported versions are {}.".format(
                    version_string,
                    ", ".join(
                        [
                            str(spec)
                            for spec in SUPPORTED_NVTICACHE_VERSIONS_SPECIFIER
                        ]
                    ),
                )
            )

    @property
    def ctx(self) -> Optional[RedisCtx]:
        if self._ctx is None:
            self._ctx, self.index = OpenvasDB.find_database_by_pattern(
                self._get_nvti_cache_name(), self._main_db.max_database_index
            )
        return self._ctx

    def get_feed_version(self) -> Optional[str]:
        """Get feed version of the nvti cache db.

        Returns the feed version or None if the nvt feed isn't available.
        """
        if not self.ctx:
            # no nvti cache db available yet
            return None

        return OpenvasDB.get_single_item(self.ctx, self._get_nvti_cache_name())

    def get_oids(self) -> Iterator[Tuple[str, str]]:
        """Get the list of NVT file names and OIDs.

        Returns:
            A i. Each single list contains the filename
            as first element and the oid as second one.
        """
        return OpenvasDB.get_filenames_and_oids(self.ctx)

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
            "nvt:%s" % oid,
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
            'timeout',
            'family',
            'name',
        ]

        custom = dict()
        custom['refs'] = dict()
        custom['vt_params'] = dict()
        for child, res in zip(subelem, resp):
            if child not in ['cve', 'bid', 'xref', 'tag', 'timeout'] and res:
                custom[child] = res
            elif child == 'tag':
                custom.update(self._parse_metadata_tags(res, oid))
            elif child in ['cve', 'bid', 'xref'] and res:
                custom['refs'][child] = res.split(", ")
            elif child == 'timeout':
                if res is None:
                    continue
                vt_params = {}
                if int(res) > 0:
                    _param_id = '0'
                    vt_params[_param_id] = dict()
                    vt_params[_param_id]['id'] = _param_id
                    vt_params[_param_id]['type'] = 'entry'
                    vt_params[_param_id]['name'] = 'timeout'
                    vt_params[_param_id]['description'] = 'Script Timeout'
                    vt_params[_param_id]['default'] = res
                custom['vt_params'] = vt_params
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
            "nvt:%s" % oid,
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

    def get_nvt_family(self, oid: str) -> str:
        """Get NVT family
        Arguments:
            oid: OID of VT from which to get the VT family.

        Returns:
            A str with the VT family.
        """
        return OpenvasDB.get_single_item(
            self.ctx,
            'nvt:%s' % oid,
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
        key = 'oid:%s:prefs' % oid
        return OpenvasDB.get_list_item(self.ctx, key)

    def get_nvt_timeout(self, oid: str) -> Optional[str]:
        """Get NVT timeout

        Arguments:
            ctx: Redis context to be used.
            oid: OID of VT from which to get the script timeout.

        Returns:
            The timeout.
        """
        return OpenvasDB.get_single_item(
            self.ctx,
            'nvt:%s' % oid,
            index=NVT_META_FIELDS.index("NVT_TIMEOUT_POS"),
        )

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
            'nvt:%s' % oid,
            index=NVT_META_FIELDS.index('NVT_TAGS_POS'),
        )
        tags = tag.split('|')

        return dict([item.split('=', 1) for item in tags])

    def get_nvt_files_count(self) -> int:
        return OpenvasDB.get_key_count(self.ctx, "filename:*")

    def get_nvt_count(self) -> int:
        return OpenvasDB.get_key_count(self.ctx, "nvt:*")

    def force_reload(self):
        self._main_db.release_database(self)
