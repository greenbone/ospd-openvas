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


from unittest import TestCase
from unittest.mock import patch, MagicMock

from ospd_openvas.feed import Feed


class FeedCommandTestCase(TestCase):
    @patch('ospd_openvas.feed.subprocess.getstatusoutput')
    def test_start_scan(self, mock_subproc: MagicMock):
        f = Feed()
        proc = f.perform_feed_sync_self_test_success()

        mock_subproc.assert_called_with('greenbone-nvt-sync --selftest')

        self.assertIsNotNone(proc)

    @patch('ospd_openvas.feed.subprocess.getstatusoutput')
    def test_start_scan_with_error(self, mock_subproc: MagicMock):
        f = Feed()
        mock_subproc.side_effect = OSError('foo')
        proc = f.perform_feed_sync_self_test_success()
        self.assertEqual(proc[0], 1)
        self.assertEqual(str(proc[1]), str(OSError('foo')))
