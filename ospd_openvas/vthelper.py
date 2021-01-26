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


""" Provide functions to handle VT Info. """

from hashlib import sha256
from typing import Optional, Dict, List, Tuple, Iterator

from ospd_openvas.nvticache import NVTICache


class VtHelper:
    def __init__(self, nvticache: NVTICache):
        self.nvti = nvticache

    def get_single_vt(self, vt_id: str, oids=None) -> Optional[Dict[str, any]]:
        custom = self.nvti.get_nvt_metadata(vt_id)

        if not custom:
            return None

        vt_params = custom.pop('vt_params')
        vt_refs = custom.pop('refs')
        name = custom.pop('name')
        vt_creation_time = custom.pop('creation_date')
        vt_modification_time = custom.pop('last_modification')

        if oids:
            vt_dependencies = list()
            if 'dependencies' in custom:
                deps = custom.pop('dependencies')
                deps_list = deps.split(', ')
                for dep_name in deps_list:
                    dep_oid = oids.get(dep_name)
                    if dep_oid:
                        vt_dependencies.append(dep_oid)
                    else:
                        vt_dependencies.append(dep_name)
        else:
            vt_dependencies = None

        summary = None
        impact = None
        affected = None
        insight = None
        solution = None
        solution_t = None
        solution_m = None
        vuldetect = None
        qod_t = None
        qod_v = None

        if 'summary' in custom:
            summary = custom.pop('summary')
        if 'impact' in custom:
            impact = custom.pop('impact')
        if 'affected' in custom:
            affected = custom.pop('affected')
        if 'insight' in custom:
            insight = custom.pop('insight')
        if 'solution' in custom:
            solution = custom.pop('solution')
            if 'solution_type' in custom:
                solution_t = custom.pop('solution_type')
            if 'solution_method' in custom:
                solution_m = custom.pop('solution_method')

        if 'vuldetect' in custom:
            vuldetect = custom.pop('vuldetect')
        if 'qod_type' in custom:
            qod_t = custom.pop('qod_type')
        elif 'qod' in custom:
            qod_v = custom.pop('qod')

        severity = dict()
        if 'severity_vector' in custom:
            severity_vector = custom.pop('severity_vector')
        else:
            severity_vector = custom.pop('cvss_base_vector')
        severity['severity_base_vector'] = severity_vector

        if "CVSS:3" in severity_vector:
            severity_type = 'cvss_base_v3'
        else:
            severity_type = 'cvss_base_v2'
        severity['severity_type'] = severity_type

        if 'severity_date' in custom:
            severity['severity_date'] = custom.pop('severity_date')
        else:
            severity['severity_date'] = vt_creation_time

        if 'severity_origin' in custom:
            severity['severity_origin'] = custom.pop('severity_origin')

        if name is None:
            name = ''

        vt = {'name': name}
        if custom is not None:
            vt["custom"] = custom
        if vt_params is not None:
            vt["vt_params"] = vt_params
        if vt_refs is not None:
            vt["vt_refs"] = vt_refs
        if vt_dependencies is not None:
            vt["vt_dependencies"] = vt_dependencies
        if vt_creation_time is not None:
            vt["creation_time"] = vt_creation_time
        if vt_modification_time is not None:
            vt["modification_time"] = vt_modification_time
        if summary is not None:
            vt["summary"] = summary
        if impact is not None:
            vt["impact"] = impact
        if affected is not None:
            vt["affected"] = affected
        if insight is not None:
            vt["insight"] = insight

        if solution is not None:
            vt["solution"] = solution
            if solution_t is not None:
                vt["solution_type"] = solution_t
            if solution_m is not None:
                vt["solution_method"] = solution_m

        if vuldetect is not None:
            vt["detection"] = vuldetect

        if qod_t is not None:
            vt["qod_type"] = qod_t
        elif qod_v is not None:
            vt["qod"] = qod_v

        if severity is not None:
            vt["severities"] = severity

        return vt

    def get_vt_iterator(
        self, vt_selection: List[str] = None, details: bool = True
    ) -> Iterator[Tuple[str, Dict]]:
        """ Yield the vts from the Redis NVTicache. """

        oids = None
        if not vt_selection or details:
            vt_collection = dict(self.nvti.get_oids())

            if not vt_selection:
                vt_selection = vt_collection.values()

            if details:
                oids = vt_collection

        for vt_id in vt_selection:
            vt = self.get_single_vt(vt_id, oids)
            yield (vt_id, vt)

    def calculate_vts_collection_hash(self) -> str:
        """ Calculate the vts collection sha256 hash. """
        m = sha256()  # pylint: disable=invalid-name

        # for a reproducible hash calculation
        # the vts must already be sorted in the dictionary.
        for vt_id, vt in self.get_vt_iterator(details=False):
            param_chain = ""
            vt_params = vt.get('vt_params')
            if vt_params:
                for _, param in sorted(vt_params.items()):
                    param_chain += (
                        param.get('id')
                        + param.get('name')
                        + param.get('default')
                    )

            m.update(
                (vt_id + vt.get('modification_time')).encode('utf-8')
                + param_chain.encode('utf-8')
            )

        return m.hexdigest()
