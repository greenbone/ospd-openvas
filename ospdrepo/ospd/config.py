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

"""
Module to store ospd configuration settings
"""

import configparser
import logging

from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


class Config:
    def __init__(self, section: str = 'main') -> None:
        self._parser = configparser.ConfigParser(default_section=section)
        self._config = {}  # type: Dict
        self._defaults = {}  # type: Dict

    def load(self, filepath: Path, def_section: str = 'main') -> None:
        path = filepath.expanduser()
        parser = configparser.ConfigParser(default_section=def_section)

        with path.open() as f:
            parser.read_file(f)

        self._defaults.update(parser.defaults())

        for key, value in parser.items(def_section):
            self._config.setdefault(def_section, dict())[key] = value

    def defaults(self) -> Dict:
        return self._defaults
