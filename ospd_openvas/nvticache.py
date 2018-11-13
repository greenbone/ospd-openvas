# -*- coding: utf-8 -*-
# Description:
# Provide functions to handle NVT Info Cache
#
# Authors:
# Juan José Nicola <juan.nicola@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

""" Functions related to the NVT information. """

# Needed to say that when we import ospd, we mean the package and not the
# module in that directory.
from __future__ import absolute_import
from __future__ import print_function

import xml.etree.ElementTree as ET
import ospd_openvas.openvas_db as openvas_db


NVTICACHE_STR = 'nvticache1.0.0'
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


def get_feed_version():
    """ Get feed version.
    """
    return openvas_db.item_get_single(NVTICACHE_STR)

def get_oids():
    """ Get the list of NVT OIDs.
    """
    return openvas_db.get_elem_pattern_by_index('filename:*')

def get_nvt_params(oid):
    """ Get NVT's preferences.
        @Return dictonary with preferences and timeout.
    """
    ctx = openvas_db.get_kb_context()
    prefs = get_nvt_prefs(ctx, oid)
    timeout = get_nvt_timeout(ctx, oid)

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

def get_nvt_metadata(oid):
    """ Get a full NVT. Returns an XML tree with the NVT metadata.
    """
    ctx = openvas_db.get_kb_context()
    resp = ctx.lrange("nvt:%s" % oid,
                      openvas_db.nvt_meta_fields.index("NVT_FILENAME_POS"),
                      openvas_db.nvt_meta_fields.index("NVT_NAME_POS"))
    if (isinstance(resp, list) and resp) is False:
        return None

    subelem = ['file_name', 'required_keys', 'mandatory_keys',
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

def get_nvt_refs(oid):
    """ Get a full NVT. Returns an XML tree with the NVT references.
    """
    ctx = openvas_db.get_kb_context()
    resp = ctx.lrange("nvt:%s" % oid,
                      openvas_db.nvt_meta_fields.index("NVT_CVES_POS"),
                      openvas_db.nvt_meta_fields.index("NVT_XREFS_POS"))
    if (isinstance(resp, list) and resp) is False:
        return None

    subelem = ['cve', 'bid', 'xref',]

    refs = dict()
    for child, res in zip(subelem, resp):
        refs[child] = res.split(", ")

    return refs

def get_nvt_name(ctx, oid):
    """ Get the NVT name of the given OID."""
    return ctx.lindex('nvt:%s' % oid,
                      openvas_db.nvt_meta_fields.index('NVT_NAME_POS'))

def get_nvt_family(ctx, oid):
    """ Get the NVT family of the given OID."""
    return ctx.lindex('nvt:%s' % oid,
                      openvas_db.nvt_meta_fields.index('NVT_FAMILY_POS'))

def get_nvt_prefs(ctx, oid):
    """ Get NVT preferences. """
    prefs = ctx.smembers('oid:%s:prefs' % oid)
    return prefs

def get_nvt_timeout(ctx, oid):
    """ Get NVT timeout"""
    timeout = ctx.lindex('nvt:%s' % oid,
                         openvas_db.nvt_meta_fields.index("NVT_TIMEOUT_POS"))
    return timeout

def get_nvt_tag(ctx, oid):
    """ Get a dictionary with the NVT Tags of the given OID."""
    tag = ctx.lindex('nvt:%s' % oid,
                      openvas_db.nvt_meta_fields.index('NVT_TAGS_POS'))
    tags = tag.split('|')

    return dict([item.split('=', 1) for item in tags])

def get_nvt_qod(ctx, tag=None, oid=None):
    """ Get the NVT QoD from a tag or from the given OID.
    @in tag A dictionary with the NVT tags
    @in oid The NVT OID
    @return QoD value as string.
    """
    if not tag:
        if oid:
            tag = get_nvt_tag(ctx, oid)
        else:
            return 0

    if tag and 'qod_type' in tag:
        qodtype = tag['qod_type']
        return QoD_TYPES[qodtype]
    elif tag and 'qod' in tag:
        return tag['qod']

    return QoD_TYPES['default']

def get_nvt_severity(ctx, tag=None, oid=None):
    """ Get the NVT Severity from a tag or from the given OID.
    @in tag A dictionary with the NVT tags
    @in oid The NVT OID
    @return Severity (cvess_base) value as string.

    """
    if not tag:
        if oid:
            tag = get_nvt_tag(ctx, oid)
        else:
            return '10'

    if tag and 'cvess_base' in tag:
        return tag['cvess_base']

    return ''
