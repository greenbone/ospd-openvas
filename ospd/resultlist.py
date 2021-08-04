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

# pylint: disable=too-many-lines

""" Class for handling list of resutls.
"""

from collections import OrderedDict
from typing import Dict
from ospd.misc import ResultType


class ResultList:
    """ Class for handling list of resutls."""

    def __init__(self):
        self._result_list = list()

    def __len__(self):
        return len(self._result_list)

    def add_scan_host_detail_to_list(
        self,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        uri: str = '',
    ) -> None:
        """ Adds a host detail result to result list. """
        self.add_result_to_list(
            ResultType.HOST_DETAIL, host, hostname, name, value, uri
        )

    def add_scan_error_to_list(
        self,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id='',
        uri: str = '',
    ) -> None:
        """ Adds an error result to result list. """
        self.add_result_to_list(
            ResultType.ERROR, host, hostname, name, value, port, test_id, uri
        )

    def add_scan_log_to_list(
        self,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        qod: str = '',
        uri: str = '',
    ) -> None:
        """ Adds log result to a list of results. """
        self.add_result_to_list(
            ResultType.LOG,
            host,
            hostname,
            name,
            value,
            port,
            test_id,
            '0.0',
            qod,
            uri,
        )

    def add_scan_alarm_to_list(
        self,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        severity: str = '',
        qod: str = '',
        uri: str = '',
    ) -> None:
        """ Adds an alarm result to a result list. """
        self.add_result_to_list(
            ResultType.ALARM,
            host,
            hostname,
            name,
            value,
            port,
            test_id,
            severity,
            qod,
            uri,
        )

    def add_result_to_list(
        self,
        result_type: int,
        host: str = '',
        hostname: str = '',
        name: str = '',
        value: str = '',
        port: str = '',
        test_id: str = '',
        severity: str = '',
        qod: str = '',
        uri: str = '',
    ) -> None:

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
        result['uri'] = uri
        self._result_list.append(result)

    def __iter__(self):
        return iter(self._result_list)
