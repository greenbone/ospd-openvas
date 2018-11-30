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

import xml.etree.ElementTree as ET
from ospd_openvas.db import OpenvasDB
from ospd_openvas.db import NVT_META_FIELDS

LIST_FIRST_POS = 0
LIST_LAST_POS = -1

class NVTICache(object):

    QoD_TYPES = {
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

    def __init__(self, openvas_db):
        self._openvas_db = openvas_db
        self.nvticache_str = 'nvticache1.0.0'

    def get_feed_version(self):
        """ Get feed version.
        """
        return self._openvas_db.get_single_item(self.nvticache_str)

    def get_oids(self):
        """ Get the list of NVT OIDs.
        """
        return self._openvas_db.get_elem_pattern_by_index('filename:*')

    def get_nvt_params(self, oid):
        """ Get NVT's preferences.
            @Return dictonary with preferences and timeout.
        """
        ctx = self._openvas_db.get_kb_context()
        prefs = self.get_nvt_prefs(ctx, oid)
        timeout = self.get_nvt_timeout(ctx, oid)

        vt_params = {}
        if int(timeout) > 0:
            vt_params['timeout'] = dict()
            vt_params['timeout']['type'] = 'entry'
            vt_params['timeout']['name'] = 'timeout'
            vt_params['timeout']['description'] = 'Script Timeout'
            vt_params['timeout']['default'] = timeout

        if prefs:
            for nvt_pref in prefs:
                elem = nvt_pref.split('|||')
                vt_params[elem[0]] = dict()
                vt_params[elem[0]]['type'] = elem[1]
                vt_params[elem[0]]['name'] = elem[0]
                vt_params[elem[0]]['description'] = 'Description'
                if elem[2]:
                    vt_params[elem[0]]['default'] = elem[2]
                else:
                    vt_params[elem[0]]['default'] = ''

        return vt_params

    def get_nvt_metadata(self, oid):
        """ Get a full NVT. Returns an XML tree with the NVT metadata.
        """
        ctx = self._openvas_db.get_kb_context()
        resp = ctx.lrange("nvt:%s" % oid,
                          NVT_META_FIELDS.index("NVT_FILENAME_POS"),
                          NVT_META_FIELDS.index("NVT_NAME_POS"))
        if (isinstance(resp, list) and resp) is False:
            return None

        subelem = ['filename', 'required_keys', 'mandatory_keys',
                   'excluded_keys', 'required_udp_ports', 'required_ports',
                   'dependencies', 'tag', 'cve', 'bid', 'xref', 'category',
                   'timeout', 'family', 'name', ]

        custom = dict()
        for child, res in zip(subelem, resp):
            if child not in ['cve', 'bid', 'xref', 'tag',] and res:
                custom[child] = res
            elif child == 'tag':
                tags = res.split('|')
                for tag in tags:
                    try:
                        _tag, _value = tag.split('=', 1)
                    except ValueError:
                        logger.error('Tag %s in %s has no value.' % (_tag, oid))
                        continue
                    custom[_tag] = _value

        return custom

    def get_nvt_refs(self, oid):
        """ Get a full NVT. Returns an XML tree with the NVT references.
        """
        ctx = self._openvas_db.get_kb_context()
        resp = ctx.lrange("nvt:%s" % oid,
                          NVT_META_FIELDS.index("NVT_CVES_POS"),
                          NVT_META_FIELDS.index("NVT_XREFS_POS"))
        if (isinstance(resp, list) and resp) is False:
            return None

        subelem = ['cve', 'bid', 'xref',]

        refs = dict()
        for child, res in zip(subelem, resp):
            refs[child] = res.split(", ")

        return refs

    def get_nvt_prefs(self, ctx, oid):
        """ Get NVT preferences. """
        key = 'oid:%s:prefs' % oid
        prefs = ctx.lrange(key, start=LIST_FIRST_POS,
                           end=LIST_LAST_POS)
        return prefs

    def get_nvt_timeout(self, ctx, oid):
        """ Get NVT timeout"""
        timeout = ctx.lindex('nvt:%s' % oid,
                             NVT_META_FIELDS.index("NVT_TIMEOUT_POS"))
        return timeout

    def get_nvt_tag(self, ctx, oid):
        """ Get a dictionary with the NVT Tags of the given OID."""
        tag = ctx.lindex('nvt:%s' % oid,
                          NVT_META_FIELDS.index('NVT_TAGS_POS'))
        tags = tag.split('|')

        return dict([item.split('=', 1) for item in tags])
