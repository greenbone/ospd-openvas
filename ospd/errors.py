# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""OSP class for handling errors."""

from ospd.xml import simple_response_str


class OspdError(Exception):
    """Base error class for all Ospd related errors"""


class RequiredArgument(OspdError):
    """Raised if a required argument/parameter is missing

    Derives from :py:class:`OspdError`
    """

    def __init__(self, function: str, argument: str) -> None:
        # pylint: disable=super-init-not-called
        self.function = function
        self.argument = argument

    def __str__(self) -> str:
        return f"{self.function}: Argument {self.argument} is required"


class OspdCommandError(OspdError):
    """This is an exception that will result in an error message to the
    client"""

    def __init__(
        self, message: str, command: str = 'osp', status: int = 400
    ) -> None:
        super().__init__(message)
        self.message = message
        self.command = command
        self.status = status

    def as_xml(self) -> str:
        """Return the error in xml format."""
        return simple_response_str(self.command, self.status, self.message)
