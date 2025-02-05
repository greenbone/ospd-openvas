# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Vulnerability Test Filter class."""
import re
import operator
from typing import Dict, List, Optional

from ospd.errors import OspdCommandError

from .vts import Vts


class VtsFilter:
    """Helper class to filter Vulnerability Tests"""

    def __init__(self) -> None:
        """Initialize filter operator and allowed filters."""
        self.filter_operator = {
            '<': operator.lt,
            '>': operator.gt,
            '=': operator.eq,
        }

        self.allowed_filter = {
            'creation_time': self.format_vt_creation_time,
            'modification_time': self.format_vt_modification_time,
        }

    def parse_filters(self, vt_filter: str) -> List:
        """Parse a string containing one or more filters
        and return a list of filters

        Arguments:
            vt_filter (string): String containing filters separated with
                semicolon.
        Return:
            List with filters. Each filters is a list with 3 elements
            e.g. [arg, operator, value]
        """

        filter_list = vt_filter.split(';')
        filters = list()

        for single_filter in filter_list:
            filter_aux = re.split(r'(\W)', single_filter, 1)

            if len(filter_aux) < 3:
                raise OspdCommandError(
                    "Invalid number of argument in the filter", "get_vts"
                )

            _element, _oper, _val = filter_aux

            if _element not in self.allowed_filter:
                raise OspdCommandError("Invalid filter element", "get_vts")

            if _oper not in self.filter_operator:
                raise OspdCommandError("Invalid filter operator", "get_vts")

            filters.append(filter_aux)

        return filters

    def format_vt_creation_time(self, value):
        """In case the given creationdatetime value must be formatted,
        this function must be implemented by the wrapper
        """
        return value

    def format_vt_modification_time(self, value):
        """In case the given modification datetime value must be formatted,
        this function must be implemented by the wrapper
        """
        return value

    def format_filter_value(self, element: str, value: Dict):
        """Calls the specific function to format value,
        depending on the given element.

        Arguments:
            element (string): The element of the VT to be formatted.
            value (dictionary): The element value.

        Returns:
            Returns a formatted value.

        """
        format_func = self.allowed_filter.get(element)
        return format_func(value)

    def get_filtered_vts_list(
        self, vts: Vts, vt_filter: str
    ) -> Optional[List[str]]:
        """Gets a collection of vulnerability test from the vts dictionary,
        which match the filter.

        Arguments:
            vt_filter: Filter to apply to the vts collection.
            vts: The complete vts collection.

        Returns:
            List with filtered vulnerability tests. The list can be empty.
            None in case of filter parse failure.
        """
        if not vt_filter:
            raise OspdCommandError('vt_filter: A valid filter is required.')

        filters = self.parse_filters(vt_filter)
        if not filters:
            return None

        vt_oid_list = list(vts)

        for _element, _oper, _filter_val in filters:
            for vt_oid in vts:
                if vt_oid not in vt_oid_list:
                    continue

                vt = vts.get(vt_oid)
                if vt is None or not vt.get(_element):
                    vt_oid_list.remove(vt_oid)
                    continue

                _elem_val = vt.get(_element)
                _val = self.format_filter_value(_element, _elem_val)

                if self.filter_operator[_oper](_val, _filter_val):
                    continue
                else:
                    vt_oid_list.remove(vt_oid)

        return vt_oid_list
