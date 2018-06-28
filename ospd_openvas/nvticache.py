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


NVTICACHE_STR = 'nvticache10'

def get_feed_version():
    """ Get feed version.
    """
    return openvas_db.item_get_single(NVTICACHE_STR)

def get_oids():
    """ Get the list of NVT OIDs.
    """
    return openvas_db.get_pattern('filename:*:oid')

def get_nvt_pref(oid):
    """ Get NVT's preferences.
        @Return XML tree with preferences
    """
    ctx = openvas_db.get_kb_context()
    resp = ctx.smembers('oid:%s:prefs' % oid)
    timeout = ctx.lindex('nvt:%s' % oid,
                         openvas_db.nvt_meta_fields.index("NVT_TIMEOUT_POS"))
    preferences = ET.Element('preferences')
    if int(timeout) > 0:
        xml_timeout = ET.Element('timeout')
        xml_timeout.text = timeout
        preferences.append(xml_timeout)

    if len(resp) > 0:
        for nvt_pref in resp:
            elem = nvt_pref.split('|||')
            preference = ET.Element('preference')
            xml_name = ET.SubElement(preference, 'name')
            xml_name.text = elem[0]
            xml_type = ET.SubElement(preference, 'type')
            xml_type.text = elem[1]
            if elem[2]:
                xml_def = ET.SubElement(preference, 'default')
                xml_def.text = elem[2]
            preferences.append(preference)

    return preferences

def get_nvt_all(oid, is_custom=0):
    """ Get a full NVT. Returns an XML tree with the NVT metadata.
    """
    ctx = openvas_db.get_kb_context()

    resp = ctx.lrange("nvt:%s" % oid,
                      openvas_db.nvt_meta_fields.index("NVT_FILENAME_POS"),
                      openvas_db.nvt_meta_fields.index("NVT_VERSION_POS"))
    if (isinstance(resp, list) and len(resp) > 0) is False:
        return None

    nvt = ET.Element('vt')
    nvt.set('id', oid)

    subelem = ['file_name', 'required_keys', 'mandatory_keys',
               'excluded_keys', 'required_udp_ports', 'required_ports',
               'dependencies', 'tag', 'cve', 'bid', 'xref', 'category',
               'timeout', 'family', 'copyright', 'name', 'version']

    for elem in subelem:
        ET.SubElement(nvt, elem)
    for child, res in zip(list(nvt), resp):
        child.text = res

    # Add preferences
    nvt.append(get_nvt_pref(oid))

    if is_custom:
        itera = nvt.iter()
        custom = ''
        for elem in itera:
            if elem.tag != 'vt' and elem.tag != 'file_name':
                custom += (ET.tostring(elem).decode('utf-8'))
        return custom

    return nvt
