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

import threading
import logging
from unittest import TestCase, mock
from ospd_openvas.messages.result import ResultMessage

from ospd_openvas.notus import NotusResultHandler


class NotusTestCase(TestCase):
    # def mock_report_func(self, results: list, scan_id: str) -> bool:
    #     pass

    def test_notus_fail_cases(self):
        def start(self):
            self.function(*self.args, **self.kwargs)

        mock_report_func = mock.MagicMock(return_value=False)
        logging.Logger.warning = mock.MagicMock()

        notus = NotusResultHandler(mock_report_func)

        res_msg = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            port="42",
            uri='file://foo/bar',
        )

        with mock.patch.object(threading.Timer, 'start', start):
            notus.result_handler(res_msg)

        logging.Logger.warning.assert_called_with(  # pylint: disable=no-member
            "Unable to report %d notus results for scan id %s.", 1, "scan_1"
        )

    def test_notus_success_case(self):
        def start(self):
            self.function(*self.args, **self.kwargs)

        mock_report_func = mock.MagicMock(return_value=True)
        logging.Logger.warning = mock.MagicMock()

        notus = NotusResultHandler(mock_report_func)

        res_msg = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            port="42",
            uri='file://foo/bar',
        )

        with mock.patch.object(threading.Timer, 'start', start):
            notus.result_handler(res_msg)

        logging.Logger.warning.assert_not_called()  # pylint: disable=no-member
