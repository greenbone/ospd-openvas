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

import logging
import subprocess

logger = logging.getLogger(__name__)


class Feed:
    """Class for getting feed info and checks"""

    def perform_feed_sync_self_test_success(self) -> tuple:
        """Calls greenbone-nvt-sync with --selftest option"""

        try:
            return subprocess.getstatusoutput("greenbone-nvt-sync --selftest")
        except (subprocess.SubprocessError, OSError) as e:
            # the command is not available
            logger.warning('Feed sync self test failed. Reason %s', e)
            return (1, e)
