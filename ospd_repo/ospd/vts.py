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

""" Classes for storing VTs
"""
import logging
import multiprocessing
from hashlib import sha256
import re

from copy import deepcopy
from typing import Dict, Any, Type, Iterator, Iterable, Tuple

from ospd.errors import OspdError

logger = logging.getLogger(__name__)

DEFAULT_VT_ID_PATTERN = re.compile("[0-9a-zA-Z_\\-:.]{1,80}")


class Vts:
    def __init__(
        self, storage: Type[Dict] = None, vt_id_pattern=DEFAULT_VT_ID_PATTERN
    ):
        self.storage = storage

        self.vt_id_pattern = vt_id_pattern
        self._vts = None
        self.sha256_hash = None

        self.is_cache_available = True

    def __contains__(self, key: str) -> bool:
        return key in self._vts

    def __iter__(self) -> Iterator[str]:
        if hasattr(self.vts, '__iter__'):
            return self.vts.__iter__()

    def __getitem__(self, key):
        return self.vts[key]

    def items(self) -> Iterator[Tuple[str, Dict]]:
        return iter(self.vts.items())

    def __len__(self) -> int:
        return len(self.vts)

    def __init_vts(self):
        if self.storage:
            self._vts = self.storage()
        else:
            self._vts = multiprocessing.Manager().dict()

    @property
    def vts(self) -> Dict[str, Any]:
        if self._vts is None:
            self.__init_vts()

        return self._vts

    def add(
        self,
        vt_id: str,
        name: str = None,
        vt_params: str = None,
        vt_refs: str = None,
        custom: str = None,
        vt_creation_time: str = None,
        vt_modification_time: str = None,
        vt_dependencies: str = None,
        summary: str = None,
        impact: str = None,
        affected: str = None,
        insight: str = None,
        solution: str = None,
        solution_t: str = None,
        solution_m: str = None,
        detection: str = None,
        qod_t: str = None,
        qod_v: str = None,
        severities: str = None,
    ) -> None:
        """Add a vulnerability test information.

        IMPORTANT: The VT's Data Manager will store the vts collection.
        If the collection is considerably big and it will be consultated
        intensible during a routine, consider to do a deepcopy(), since
        accessing the shared memory in the data manager is very expensive.
        At the end of the routine, the temporal copy must be set to None
        and deleted.
        """
        if not vt_id:
            raise OspdError('Invalid vt_id {}'.format(vt_id))

        if self.vt_id_pattern.fullmatch(vt_id) is None:
            raise OspdError('Invalid vt_id {}'.format(vt_id))

        if vt_id in self.vts:
            raise OspdError('vt_id {} already exists'.format(vt_id))

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

        if detection is not None:
            vt["detection"] = detection

        if qod_t is not None:
            vt["qod_type"] = qod_t
        elif qod_v is not None:
            vt["qod"] = qod_v

        if severities is not None:
            vt["severities"] = severities

        self.vts[vt_id] = vt

    def get(self, vt_id: str) -> Dict[str, Any]:
        return self.vts.get(vt_id)

    def keys(self) -> Iterable[str]:
        return self.vts.keys()

    def clear(self) -> None:
        self._vts.clear()
        self._vts = None

    def copy(self) -> "Vts":
        copy = Vts(self.storage, vt_id_pattern=self.vt_id_pattern)
        copy._vts = deepcopy(self._vts)  # pylint: disable=protected-access
        return copy

    def calculate_vts_collection_hash(self, include_vt_params: bool = True):
        """ Calculate the vts collection sha256 hash. """
        if not self._vts:
            logger.debug(
                "Error calculating VTs collection hash. Cache is empty"
            )
            return

        m = sha256()  # pylint: disable=invalid-name

        # for a reproducible hash calculation
        # the vts must already be sorted in the dictionary.
        for vt_id, vt in self.vts.items():
            param_chain = ""
            vt_params = vt.get('vt_params')
            if include_vt_params and vt_params:
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

        self.sha256_hash = m.hexdigest()
