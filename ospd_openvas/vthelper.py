# -*- coding: utf-8 -*-
# Copyright (C) 2014-2020 Greenbone Networks GmbH
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

from typing import Optional, Dict, List, Tuple, Iterator

from ospd_openvas.nvticache import NVTICache


class VtHelper:
    def __init__(self, nvticache: NVTICache):
        self.nvti = nvticache

    def get_single_vt(self, vt_id: str, oids=None) -> Optional[Dict[str, any]]:
        _custom = self.nvti.get_nvt_metadata(vt_id)

        if not _custom:
            return None

        _vt_params = _custom.pop('vt_params')
        _vt_refs = _custom.pop('refs')
        _name = _custom.pop('name')
        _vt_creation_time = _custom.pop('creation_date')
        _vt_modification_time = _custom.pop('last_modification')

        if oids:
            _vt_dependencies = list()
            if 'dependencies' in _custom:
                _deps = _custom.pop('dependencies')
                _deps_list = _deps.split(', ')
                for dep in _deps_list:
                    _vt_dependencies.append(oids.get(dep))
        else:
            _vt_dependencies = None

        _summary = None
        _impact = None
        _affected = None
        _insight = None
        _solution = None
        _solution_t = None
        _vuldetect = None
        _qod_t = None
        _qod_v = None

        if 'summary' in _custom:
            _summary = _custom.pop('summary')
        if 'impact' in _custom:
            _impact = _custom.pop('impact')
        if 'affected' in _custom:
            _affected = _custom.pop('affected')
        if 'insight' in _custom:
            _insight = _custom.pop('insight')
        if 'solution' in _custom:
            _solution = _custom.pop('solution')
            if 'solution_type' in _custom:
                _solution_t = _custom.pop('solution_type')

        if 'vuldetect' in _custom:
            _vuldetect = _custom.pop('vuldetect')
        if 'qod_type' in _custom:
            _qod_t = _custom.pop('qod_type')
        elif 'qod' in _custom:
            _qod_v = _custom.pop('qod')

        _severity = dict()
        if 'severity_base_vector' in _custom:
            _severity_vector = _custom.pop('severity_base_vector')
        else:
            _severity_vector = _custom.pop('cvss_base_vector')
        _severity['severity_base_vector'] = _severity_vector
        if 'severity_type' in _custom:
            _severity_type = _custom.pop('severity_type')
        else:
            _severity_type = 'cvss_base_v2'
        _severity['severity_type'] = _severity_type
        if 'severity_origin' in _custom:
            _severity['severity_origin'] = _custom.pop('severity_origin')

        if _name is None:
            _name = ''

        vt = {'name': _name}
        if _custom is not None:
            vt["custom"] = _custom
        if _vt_params is not None:
            vt["vt_params"] = _vt_params
        if _vt_refs is not None:
            vt["vt_refs"] = _vt_refs
        if _vt_dependencies is not None:
            vt["vt_dependencies"] = _vt_dependencies
        if _vt_creation_time is not None:
            vt["creation_time"] = _vt_creation_time
        if _vt_modification_time is not None:
            vt["modification_time"] = _vt_modification_time
        if _summary is not None:
            vt["summary"] = _summary
        if _impact is not None:
            vt["impact"] = _impact
        if _affected is not None:
            vt["affected"] = _affected
        if _insight is not None:
            vt["insight"] = _insight

        if _solution is not None:
            vt["solution"] = _solution
            if _solution_t is not None:
                vt["solution_type"] = _solution_t

        if _vuldetect is not None:
            vt["detection"] = _vuldetect

        if _qod_t is not None:
            vt["qod_type"] = _qod_t
        elif _qod_v is not None:
            vt["qod"] = _qod_v

        if _severity is not None:
            vt["severities"] = _severity

        return vt

    def get_vt_iterator(
        self, vt_selection: List[str] = None, details: bool = True
    ) -> Iterator[Tuple[str, Dict]]:
        """ Yield the vts from the Redis NVTicache. """

        oids = None
        if details:
            oids = dict(self.nvti.get_oids())

        for vt_id in vt_selection:
            vt = self.get_single_vt(vt_id, oids)
            yield (vt_id, vt)
