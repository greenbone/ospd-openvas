# -*- coding: utf-8 -*-
# Copyright (C) 2018 Greenbone Networks GmbH
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

""" Provide functions to handle NVT Info Cache. """

import logging

from ospd_openvas.db import NVT_META_FIELDS

logger = logging.getLogger(__name__)

LIST_FIRST_POS = 0
LIST_LAST_POS = -1


class NVTICache(object):

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

    NVTICACHE_STR = 'nvticache11.0.0'

    def __init__(self, openvas_db):
        self._openvas_db = openvas_db

    def get_feed_version(self):
        """ Get feed version.
        """
        ctx = self._openvas_db.db_find(self.NVTICACHE_STR)
        return self._openvas_db.get_single_item(self.NVTICACHE_STR, ctx=ctx)

    def get_oids(self):
        """ Get the list of NVT OIDs.
        Returns:
            list: A list of lists. Each single list contains the filename
            as first element and the oid as second one.
        """
        return self._openvas_db.get_elem_pattern_by_index('filename:*')

    def get_nvt_params(self, oid):
        """ Get NVT's preferences.
        Arguments:
            oid (str) OID of VT from which to get the parameters.
        Returns:
            dict: A dictionary with preferences and timeout.
        """
        ctx = self._openvas_db.get_kb_context()
        prefs = self.get_nvt_prefs(ctx, oid)
        timeout = self.get_nvt_timeout(ctx, oid)

        vt_params = {}
        if int(timeout) > 0:
            _param_id = '0'
            vt_params[_param_id] = dict()
            vt_params[_param_id]['id'] = _param_id
            vt_params[_param_id]['type'] = 'entry'
            vt_params[_param_id]['name'] = 'timeout'
            vt_params[_param_id]['description'] = 'Script Timeout'
            vt_params[_param_id]['default'] = timeout

        if prefs:
            for nvt_pref in prefs:
                elem = nvt_pref.split('|||')
                _param_id = elem[0]
                vt_params[_param_id] = dict()
                vt_params[_param_id]['id'] = _param_id
                vt_params[_param_id]['type'] = elem[2]
                vt_params[_param_id]['name'] = elem[1].strip()
                vt_params[_param_id]['description'] = 'Description'
                if elem[2]:
                    vt_params[_param_id]['default'] = elem[3]
                else:
                    vt_params[_param_id]['default'] = ''

        return vt_params

    @staticmethod
    def _parse_metadata_tags(tags_str, oid):
        """ Parse a string with multiple tags.

        Arguments:
            tags_str (str) String with tags separated by `|`.
            oid (str) VT OID. Only used for logging in error case.

        Returns:
            dict: A dictionary with the tags.
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

    def get_nvt_metadata(self, oid):
        """ Get a full NVT. Returns an XML tree with the NVT metadata.
        Arguments:
            oid (str) OID of VT from which to get the metadata.
        Returns:
            dict: A dictonary with the VT metadata.
        """
        ctx = self._openvas_db.get_kb_context()
        resp = self._openvas_db.get_list_item(
            "nvt:%s" % oid,
            ctx=ctx,
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
        for child, res in zip(subelem, resp):
            if child not in ['cve', 'bid', 'xref', 'tag'] and res:
                custom[child] = res
            elif child == 'tag':
                custom.update(self._parse_metadata_tags(res, oid))

        return custom

    def get_nvt_refs(self, oid):
        """ Get a full NVT.
        Arguments:
            oid (str) OID of VT from which to get the VT references.
        Returns:
            dict: A dictionary with the VT references.
        """
        ctx = self._openvas_db.get_kb_context()
        resp = self._openvas_db.get_list_item(
            "nvt:%s" % oid,
            ctx=ctx,
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

    def get_nvt_prefs(self, ctx, oid):
        """ Get NVT preferences.
        Arguments:
            ctx (object): Redis context to be used.
            oid (str) OID of VT from which to get the VT preferences.
        Returns:
            list: A list with the VT preferences.
        """
        key = 'oid:%s:prefs' % oid
        prefs = self._openvas_db.get_list_item(key, ctx=ctx)
        return prefs

    def get_nvt_timeout(self, ctx, oid):
        """ Get NVT timeout
        Arguments:
            ctx (object): Redis context to be used.
            oid (str) OID of VT from which to get the script timeout.
        Returns:
            str: The timeout.
        """
        timeout = self._openvas_db.get_single_item(
            'nvt:%s' % oid,
            ctx=ctx,
            index=NVT_META_FIELDS.index("NVT_TIMEOUT_POS"),
        )

        return timeout

    def get_nvt_tag(self, ctx, oid):
        """ Get Tags of the given OID.
        Arguments:
            ctx (object): Redis context to be used.
            oid (str) OID of VT from which to get the VT tags.
        Returns:
            dict: A dictionary with the VT tags.
        """
        tag = self._openvas_db.get_single_item(
            'nvt:%s' % oid, ctx=ctx, index=NVT_META_FIELDS.index('NVT_TAGS_POS')
        )
        tags = tag.split('|')

        return dict([item.split('=', 1) for item in tags])
