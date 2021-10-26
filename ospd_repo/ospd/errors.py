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

""" OSP class for handling errors.
"""

from ospd.xml import simple_response_str


class OspdError(Exception):
    """ Base error class for all Ospd related errors """


class RequiredArgument(OspdError):
    """Raised if a required argument/parameter is missing

    Derives from :py:class:`OspdError`
    """

    def __init__(self, function: str, argument: str) -> None:
        # pylint: disable=super-init-not-called
        self.function = function
        self.argument = argument

    def __str__(self) -> str:
        return "{}: Argument {} is required".format(
            self.function, self.argument
        )


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
        """ Return the error in xml format. """
        return simple_response_str(self.command, self.status, self.message)
