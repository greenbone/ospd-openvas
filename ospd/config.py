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


def strtoboolean(value: str) -> bool:
    """Convert string *value* to boolean.

    "True", "yes", "on" and "1" are converted to True.

    "False", "no", "off" and "0" are converted to False.

    Comparison is done case insensitive.

    Other values cause ValueError.
    """
    trues = set(element.casefold() for element in ["true", "yes", "on", "1"])
    falses = set(element.casefold() for element in ["false", "no", "off", "0"])
    if value.casefold() in trues:
        return True
    if value.casefold() in falses:
        return False
    raise ValueError(f"{value} could not be converted to boolean")


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
