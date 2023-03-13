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

""" OSP XML utils class for VTs.
"""
import logging

from typing import List, Dict, Optional
from lxml.etree import Element, SubElement, tostring

logger = logging.getLogger(__name__)

VT_BASE_OID = "1.3.6.1.4.1.25623."


class XmlStringVTHelper:
    """Class with methods to help the creation of a VT's xml object in
    string format.
    """

    @staticmethod
    def get_custom_vt_as_xml_str(vt_id: str, custom: Dict) -> str:
        """Return an xml element with custom metadata formatted as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            custom: Dictionary with the custom metadata.
        Return:
            Xml element as string.
        """

        _custom = Element('custom')
        for key, val in custom.items():
            xml_key = SubElement(_custom, key)
            try:
                xml_key.text = val
            except ValueError as e:
                logger.warning(
                    "Not possible to parse custom tag for VT %s: %s", vt_id, e
                )
        return tostring(_custom).decode('utf-8')

    @staticmethod
    def get_severities_vt_as_xml_str(vt_id: str, severities: Dict) -> str:
        """Return an xml element with severities as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            severities: Dictionary with the severities.
        Return:
            Xml element as string.
        """
        _severities = Element('severities')
        _severity = SubElement(_severities, 'severity')
        if 'severity_base_vector' in severities:
            try:
                _value = SubElement(_severity, 'value')
                _value.text = severities.get('severity_base_vector')
            except ValueError as e:
                logger.warning(
                    "Not possible to parse severity tag for vt %s: %s", vt_id, e
                )
        if 'severity_origin' in severities:
            _origin = SubElement(_severity, 'origin')
            _origin.text = severities.get('severity_origin')
        if 'severity_date' in severities:
            _date = SubElement(_severity, 'date')
            _date.text = severities.get('severity_date')
        if 'severity_type' in severities:
            _severity.set('type', severities.get('severity_type'))

        return tostring(_severities).decode('utf-8')

    @staticmethod
    def get_params_vt_as_xml_str(vt_id: str, vt_params: Dict) -> str:
        """Return an xml element with params formatted as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_params: Dictionary with the VT parameters.
        Return:
            Xml element as string.
        """
        vt_params_xml = Element('params')
        for _pref_id, prefs in vt_params.items():
            vt_param = Element('param')
            vt_param.set('type', prefs['type'])
            vt_param.set('id', _pref_id)
            xml_name = SubElement(vt_param, 'name')
            try:
                xml_name.text = prefs['name']
            except ValueError as e:
                logger.warning(
                    "Not possible to parse parameter for VT %s: %s", vt_id, e
                )
            if prefs['default']:
                xml_def = SubElement(vt_param, 'default')
                try:
                    xml_def.text = prefs['default']
                except ValueError as e:
                    logger.warning(
                        "Not possible to parse default parameter for VT %s: %s",
                        vt_id,
                        e,
                    )
            vt_params_xml.append(vt_param)

        return tostring(vt_params_xml).decode('utf-8')

    @staticmethod
    def get_refs_vt_as_xml_str(vt_id: str, vt_refs: Dict) -> str:
        """Return an xml element with references formatted as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_refs: Dictionary with the VT references.
        Return:
            Xml element as string.
        """
        vt_refs_xml = Element('refs')
        for ref_type, ref_values in vt_refs.items():
            for value in ref_values:
                vt_ref = Element('ref')
                if ref_type == "xref" and value:
                    for xref in value.split(', '):
                        try:
                            _type, _id = xref.split(':', 1)
                        except ValueError as e:
                            logger.error(
                                'Not possible to parse xref "%s" for VT %s: %s',
                                xref,
                                vt_id,
                                e,
                            )
                            continue
                        vt_ref.set('type', _type.lower())
                        vt_ref.set('id', _id)
                elif value:
                    vt_ref.set('type', ref_type.lower())
                    vt_ref.set('id', value)
                else:
                    continue
                vt_refs_xml.append(vt_ref)

        return tostring(vt_refs_xml).decode('utf-8')

    @staticmethod
    def get_dependencies_vt_as_xml_str(
        vt_id: str, vt_dependencies: List
    ) -> str:
        """Return  an xml element with dependencies as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_dependencies: List with the VT dependencies.
        Return:
            Xml element as string.
        """
        vt_deps_xml = Element('dependencies')
        for dep in vt_dependencies:
            _vt_dep = Element('dependency')
            if VT_BASE_OID in dep:
                _vt_dep.set('vt_id', dep)
            else:
                logger.error(
                    'Not possible to add dependency %s for VT %s', dep, vt_id
                )
                continue
            vt_deps_xml.append(_vt_dep)

        return tostring(vt_deps_xml).decode('utf-8')

    @staticmethod
    def get_creation_time_vt_as_xml_str(
        vt_id: str, vt_creation_time: str
    ) -> str:
        """Return creation time as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_creation_time: String with the VT creation time.
        Return:
           Xml element as string.
        """
        _time = Element('creation_time')
        try:
            _time.text = vt_creation_time
        except ValueError as e:
            logger.warning(
                "Not possible to parse creation time for VT %s: %s", vt_id, e
            )
        return tostring(_time).decode('utf-8')

    @staticmethod
    def get_modification_time_vt_as_xml_str(
        vt_id: str, vt_modification_time: str
    ) -> str:
        """Return modification time as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_modification_time: String with the VT modification time.
        Return:
            Xml element as string.
        """
        _time = Element('modification_time')
        try:
            _time.text = vt_modification_time
        except ValueError as e:
            logger.warning(
                "Not possible to parse modification time for VT %s: %s",
                vt_id,
                e,
            )
        return tostring(_time).decode('utf-8')

    @staticmethod
    def get_summary_vt_as_xml_str(vt_id: str, summary: str) -> str:
        """Return summary as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            summary: String with a VT summary.
        Return:
            Xml element as string.
        """
        _summary = Element('summary')
        try:
            _summary.text = summary
        except ValueError as e:
            logger.warning(
                "Not possible to parse summary tag for VT %s: %s", vt_id, e
            )

        return tostring(_summary).decode('utf-8')

    @staticmethod
    def get_impact_vt_as_xml_str(vt_id: str, impact) -> str:
        """Return impact as string.

        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            impact (str): String which explain the vulneravility impact.
        Return:
            string: xml element as string.
        """
        _impact = Element('impact')
        try:
            _impact.text = impact
        except ValueError as e:
            logger.warning(
                "Not possible to parse impact tag for VT %s: %s", vt_id, e
            )
        return tostring(_impact).decode('utf-8')

    @staticmethod
    def get_affected_vt_as_xml_str(vt_id: str, affected: str) -> str:
        """Return affected as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            affected: String which explain what is affected.
        Return:
            Xml element as string.
        """
        _affected = Element('affected')
        try:
            _affected.text = affected
        except ValueError as e:
            logger.warning(
                "Not possible to parse affected tag for VT %s: %s", vt_id, e
            )
        return tostring(_affected).decode('utf-8')

    @staticmethod
    def get_insight_vt_as_xml_str(vt_id: str, insight: str) -> str:
        """Return insight as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            insight: String giving an insight of the vulnerability.
        Return:
            Xml element as string.
        """
        _insight = Element('insight')
        try:
            _insight.text = insight
        except ValueError as e:
            logger.warning(
                "Not possible to parse insight tag for VT %s: %s", vt_id, e
            )
        return tostring(_insight).decode('utf-8')

    @staticmethod
    def get_solution_vt_as_xml_str(
        vt_id: str,
        solution: str,
        solution_type: Optional[str] = None,
        solution_method: Optional[str] = None,
    ) -> str:
        """Return solution as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            solution: String giving a possible solution.
            solution_type: A solution type
            solution_method: A solution method
        Return:
            Xml element as string.
        """
        _solution = Element('solution')
        try:
            _solution.text = solution
        except ValueError as e:
            logger.warning(
                "Not possible to parse solution tag for VT %s: %s", vt_id, e
            )
        if solution_type:
            _solution.set('type', solution_type)
        if solution_method:
            _solution.set('method', solution_method)
        return tostring(_solution).decode('utf-8')

    @staticmethod
    def get_detection_vt_as_xml_str(
        vt_id: str,
        detection: Optional[str] = None,
        qod_type: Optional[str] = None,
        qod: Optional[str] = None,
    ) -> str:
        """Return detection as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            detection: String which explain how the vulnerability
              was detected.
            qod_type: qod type.
            qod: qod value.
        Return:
            Xml element as string.
        """
        _detection = Element('detection')
        if detection:
            try:
                _detection.text = detection
            except ValueError as e:
                logger.warning(
                    "Not possible to parse detection tag for VT %s: %s",
                    vt_id,
                    e,
                )
        if qod_type:
            _detection.set('qod_type', qod_type)
        elif qod:
            _detection.set('qod', qod)

        return tostring(_detection).decode('utf-8')
