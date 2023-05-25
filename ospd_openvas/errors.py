# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module for OSPD OpenVAS errors
"""

from ospd.errors import OspdError


class OspdOpenvasError(OspdError):
    """An exception for gvm errors

    Base class for all exceptions originated in ospd-openvas.
    """
