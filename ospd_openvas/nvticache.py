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

def get_nvt_params(oid, str_format=False):
    """ Get NVT's preferences.
        @Return XML tree with preferences
    """
    ctx = openvas_db.get_kb_context()
    resp = ctx.smembers('oid:%s:prefs' % oid)
    timeout = ctx.lindex('nvt:%s' % oid,
                         openvas_db.nvt_meta_fields.index("NVT_TIMEOUT_POS"))
    vt_params = ET.Element('vt_params')
    if int(timeout) > 0:
        vt_param = ET.Element('vt_param')
        vt_param.set('id', 'timeout')
        vt_param.set('type', 'entry')
        xml_name = ET.SubElement(vt_param, 'name')
        xml_name.text = "Timeout"
        xml_desc =  ET.SubElement(vt_param, 'description')
        xml_desc.text = "Script Timeout"
        xml_def = ET.SubElement(vt_param, 'default')
        xml_def.text = timeout
        vt_params.append(vt_param)

    if resp:
        for nvt_pref in resp:
            elem = nvt_pref.split('|||')
            vt_param = ET.Element('vt_param')
            vt_param.set('id', elem[0])
            vt_param.set('type', elem[1])
            xml_name = ET.SubElement(vt_param, 'name')
            xml_name.text = elem[0]
            if elem[2]:
                xml_def = ET.SubElement(vt_param, 'default')
                xml_def.text = elem[2]
            xml_desc =  ET.SubElement(vt_param, 'description')
            vt_params.append(vt_param)

    if str_format:
        params_list = vt_params.findall("vt_param")
        params = ''
        for param in params_list:
            params += (ET.tostring(param).decode('utf-8'))
        return params

    return vt_params

def get_nvt_metadata(oid, str_format=False):
    """ Get a full NVT. Returns an XML tree with the NVT metadata.
    """
    ctx = openvas_db.get_kb_context()

    resp = ctx.lrange("nvt:%s" % oid,
                      openvas_db.nvt_meta_fields.index("NVT_FILENAME_POS"),
                      openvas_db.nvt_meta_fields.index("NVT_VERSION_POS"))
    if (isinstance(resp, list) and resp) is False:
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

    if str_format:
        itera = nvt.iter()
        metadata = ''
        for elem in itera:
            if elem.tag != 'vt' and elem.tag != 'file_name':
                metadata += (ET.tostring(elem).decode('utf-8'))
        return metadata

    return nvt
