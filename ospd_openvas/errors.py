# -*- coding: utf-8 -*-
# Copyright (C) 2018 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Module for OSPD OpenVAS errors
"""

from ospd.error import OSPDError


class OSPDOpenvasError(OSPDError):
    """An exception for gvm errors

    Base class for all exceptions originated in ospd-openvas.
    """
    def __init__(self, message):
        pass

class InvalidArgument(OSPDOpenvasError):
    """Raised if an invalid argument/parameter is passed

    Derives from :py:class:`OSPDOpenvasError`
    """

class RequiredArgument(OSPDOpenvasError):
    """Raised if a required argument/parameter is missing

    Derives from :py:class:`OSPDOpenvasError`
    """
