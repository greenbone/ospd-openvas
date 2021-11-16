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

""" Common Vulnerability Scoring System handling class. """

import math
from typing import List, Dict, Optional

CVSS_V2_METRICS = {
    'AV': {'L': 0.395, 'A': 0.646, 'N': 1.0},
    'AC': {'H': 0.35, 'M': 0.61, 'L': 0.71},
    'Au': {'M': 0.45, 'S': 0.56, 'N': 0.704},
    'C': {'N': 0.0, 'P': 0.275, 'C': 0.660},
    'I': {'N': 0.0, 'P': 0.275, 'C': 0.660},
    'A': {'N': 0.0, 'P': 0.275, 'C': 0.660},
}  # type: Dict

CVSS_V3_METRICS = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR_SU': {'N': 0.85, 'L': 0.62, 'H': 0.27},
    'PR_SC': {'N': 0.85, 'L': 0.68, 'H': 0.50},
    'UI': {'N': 0.85, 'R': 0.62},
    'S': {'U': False, 'C': True},
    'C': {'H': 0.56, 'L': 0.22, 'N': 0},
    'I': {'H': 0.56, 'L': 0.22, 'N': 0},
    'A': {'H': 0.56, 'L': 0.22, 'N': 0},
}  # type: Dict


class CVSS(object):
    """ Handle cvss vectors and calculate the cvss scoring"""

    @staticmethod
    def roundup(value: float) -> float:
        """It rounds up to 1 decimal. """
        return math.ceil(value * 10) / 10

    @staticmethod
    def _parse_cvss_base_vector(cvss_vector: str) -> List:
        """Parse a string containing a cvss base vector.

        Arguments:
            cvss_vector (str): cvss base vector to be parsed.

        Return list with the string values of each vector element.
        """
        vector_as_list = cvss_vector.split('/')
        return [item.split(':')[1] for item in vector_as_list]

    @classmethod
    def cvss_base_v2_value(cls, cvss_base_vector: str) -> Optional[float]:
        """Calculate the cvss base score from a cvss base vector
        for cvss version 2.
        Arguments:
            cvss_base_vector (str) Cvss base vector v2.

        Return the calculated score
        """
        if not cvss_base_vector:
            return None

        _av, _ac, _au, _c, _i, _a = cls._parse_cvss_base_vector(
            cvss_base_vector
        )

        _impact = 10.41 * (
            1
            - (1 - CVSS_V2_METRICS['C'].get(_c))
            * (1 - CVSS_V2_METRICS['I'].get(_i))
            * (1 - CVSS_V2_METRICS['A'].get(_a))
        )

        _exploitability = (
            20
            * CVSS_V2_METRICS['AV'].get(_av)
            * CVSS_V2_METRICS['AC'].get(_ac)
            * CVSS_V2_METRICS['Au'].get(_au)
        )

        f_impact = 0 if _impact == 0 else 1.176

        cvss_base = ((0.6 * _impact) + (0.4 * _exploitability) - 1.5) * f_impact

        return round(cvss_base, 1)

    @classmethod
    def cvss_base_v3_value(cls, cvss_base_vector: str) -> Optional[float]:
        """Calculate the cvss base score from a cvss base vector
        for cvss version 3.
        Arguments:
            cvss_base_vector (str) Cvss base vector v3.

        Return the calculated score, None on fail.
        """
        if not cvss_base_vector:
            return None
        _ver, _av, _ac, _pr, _ui, _s, _c, _i, _a = cls._parse_cvss_base_vector(
            cvss_base_vector
        )

        scope_changed = CVSS_V3_METRICS['S'].get(_s)

        isc_base = 1 - (
            (1 - CVSS_V3_METRICS['C'].get(_c))
            * (1 - CVSS_V3_METRICS['I'].get(_i))
            * (1 - CVSS_V3_METRICS['A'].get(_a))
        )

        if scope_changed:
            _priv_req = CVSS_V3_METRICS['PR_SC'].get(_pr)
        else:
            _priv_req = CVSS_V3_METRICS['PR_SU'].get(_pr)

        _exploitability = (
            8.22
            * CVSS_V3_METRICS['AV'].get(_av)
            * CVSS_V3_METRICS['AC'].get(_ac)
            * _priv_req
            * CVSS_V3_METRICS['UI'].get(_ui)
        )

        if scope_changed:
            _impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(
                isc_base - 0.02, 15
            )
            _base_score = min(1.08 * (_impact + _exploitability), 10)
        else:
            _impact = 6.42 * isc_base
            _base_score = min(_impact + _exploitability, 10)

        if _impact > 0:
            return cls.roundup(_base_score)

        return 0
