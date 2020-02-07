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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

from typing import List

__COMMANDS = []


def register_command(command: object) -> None:
    """ Register a command class
    """
    __COMMANDS.append(command)


def remove_command(command: object) -> None:
    """ Unregister a command class
    """
    __COMMANDS.remove(command)


def get_commands() -> List[object]:
    """ Return the list of registered command classes
    """
    return __COMMANDS
