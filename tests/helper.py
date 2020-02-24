# -*- coding: utf-8 -*-
# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

from unittest.mock import Mock


def assert_called_once(mock: Mock):
    if hasattr(mock, 'assert_called_once'):
        return mock.assert_called_once()

    if not mock.call_count == 1:
        msg = "Expected '%s' to have been called once. Called %s times.%s" % (
            mock._mock_name or 'mock',  # pylint: disable=protected-access
            mock.call_count,
            mock._calls_repr(),  # pylint: disable=protected-access
        )
        raise AssertionError(msg)


def assert_called(mock: Mock):
    """assert that the mock was called at least once
    """
    if mock.call_count == 0:
        msg = "Expected '%s' to have been called." % (mock._mock_name or 'mock')
        raise AssertionError(msg)
