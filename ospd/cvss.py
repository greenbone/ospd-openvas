# Copyright (C) 2014-2018 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

""" Common Vulnerability Scoring System handling class. """

cvss_base_v2 = {
    'AV': {'L': 0.395, 'A': 0.646, 'N': 1.0},
    'AC': {'H': 0.35 , 'M': 0.61, 'L': 0.71},
    'Au': {'M': 0.45, 'S': 0.56,'N': 0.704},
    'C': {'N': 0.0, 'P': 0.275,'C': 0.660},
    'I': {'N': 0.0, 'P': 0.275,'C': 0.660},
    'A': {'N': 0.0, 'P': 0.275,'C': 0.660},
}


class CVSS(object):
    """ Handle cvss vectors """

    @staticmethod
    def _parse_cvss_v2_base_vector(cvss_vector):
        """Parse a string containing a cvss base vector.

        Arguments:
            cvss_vector (str): cvss base vector to be parsed.

        Return list with the string values of each vector element.
        """
        vector_as_list = cvss_vector.split('/')
        return [item.split(':')[1] for item in vector_as_list]

    @classmethod
    def cvss_base_v2_value(cls, cvss_base_vector):
        """ Calculate the cvss base score from a cvss base vector
        for cvss version 2.
        Arguments:
            cvss_base_vector (str) Cvss base vector v2.

        Return the calculated score
        """
        if not cvss_base_vector:
            return None

        _av, _ac, _au, _c, _i, _a = cls._parse_cvss_v2_base_vector(
            cvss_base_vector)

        _impact = 10.41 * (1 - (1 - cvss_base_v2['C'].get(_c)) *
                           (1 - cvss_base_v2['I'].get(_i)) *
                           (1 - cvss_base_v2['A'].get(_a)))

        _exploitability = (20 * cvss_base_v2['AV'].get(_av) *
                           cvss_base_v2['AC'].get(_ac) *
                           cvss_base_v2['Au'].get(_au))

        f_impact = 0 if _impact == 0 else 1.176

        cvss_base = ((0.6 * _impact) + (0.4 * _exploitability) - 1.5) * f_impact

        return round(cvss_base, 1)
