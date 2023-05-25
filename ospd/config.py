# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

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
