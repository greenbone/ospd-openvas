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

# pylint: disable=too-many-lines

""" Class for handling list of resutls.
"""

from collections import OrderedDict
from typing import (
    List,
    Dict,
    Optional,
)
from ospd.misc import ResultType


class ResultList:
    """ Class for handling list of resutls."""

    def add_scan_host_detail_to_list(
        self,
        result_list: Optional[List],
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
    ) -> List[Dict[str, str]]:
        """ Adds a host detail result to result list. """
        result_list = self.add_result_to_list(
            result_list, ResultType.HOST_DETAIL, host, hostname, name, value,
        )
        return result_list

    def add_scan_error_to_list(
        self,
        result_list: Optional[List],
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id='',
    ) -> List[Dict[str, str]]:
        """ Adds an error result to result list. """
        result_list = self.add_result_to_list(
            result_list,
            ResultType.ERROR,
            host,
            hostname,
            name,
            value,
            port,
            test_id,
        )
        return result_list

    def add_scan_log_to_list(
        self,
        result_list: Optional[List],
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        qod: str = '',
    ) -> List[Dict[str, str]]:
        """ Adds log result to a list of results. """
        result_list = self.add_result_to_list(
            result_list,
            ResultType.LOG,
            host,
            hostname,
            name,
            value,
            port,
            test_id,
            '0.0',
            qod,
        )
        return result_list

    def add_scan_alarm_to_list(
        self,
        result_list: Optional[List],
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        severity: str = '',
        qod: str = '',
    ) -> List[Dict[str, str]]:
        """ Adds an alarm result to a result list. """
        result_list = self.add_result_to_list(
            result_list,
            ResultType.ALARM,
            host,
            hostname,
            name,
            value,
            port,
            test_id,
            severity,
            qod,
        )
        return result_list

    def add_result_to_list(
        self,
        results: List[Dict[str, str]],
        result_type: int,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        severity: str = '',
        qod: str = '',
    ) -> List[Dict[str, str]]:

        result = OrderedDict()  # type: Dict
        result['type'] = result_type
        result['name'] = name
        result['severity'] = severity
        result['test_id'] = test_id
        result['value'] = value
        result['host'] = host
        result['hostname'] = hostname
        result['port'] = port
        result['qod'] = qod

        if results is None:
            results = list()
        results.append(result)

        return results
