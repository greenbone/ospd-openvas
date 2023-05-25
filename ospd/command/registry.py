# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from typing import List

__COMMANDS = []


def register_command(command: object) -> None:
    """Register a command class"""
    __COMMANDS.append(command)


def remove_command(command: object) -> None:
    """Unregister a command class"""
    __COMMANDS.remove(command)


def get_commands() -> List[object]:
    """Return the list of registered command classes"""
    return __COMMANDS
