# -*- coding: utf-8 -*-
# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
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
Module to store ospd configuration settings
"""

import configparser
import logging

logger = logging.getLogger(__name__)

class Config:
    def __init__(self, section='main'):
        self._config = configparser.ConfigParser(default_section=section)
        self._config = {}
        self._defaults = dict()

    def load(self, filepath, def_section='main'):
        path = filepath.expanduser()

        config = configparser.ConfigParser(default_section=def_section)

        with path.open() as f:
            config.read_file(f)

        self._defaults.update(config.defaults())

        for key, value in config.items(def_section):
                self._config.setdefault(def_section, dict())[key] = value

    def defaults(self):
        return self._defaults
