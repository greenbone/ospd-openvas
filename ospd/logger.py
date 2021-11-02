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

import logging
import os
import configparser

from logging.config import fileConfig
from pathlib import Path
from typing import Optional


DEFAULT_HANDLER_CONSOLE = {
    'class': 'logging.StreamHandler',
    'level': 'INFO',
    'formatter': 'file',
    'args': 'sys.stdout,',
}

DEFAULT_HANDLER_FILE = {
    'class': 'FileHandler',
    'level': 'INFO',
    'formatter': 'file',
}

DEFAULT_HANDLER_SYSLOG = {
    'class': 'handlers.SysLogHandler',
    'level': 'INFO',
    'formatter': 'syslog',
    'args': '("/dev/log", handlers.SysLogHandler.LOG_USER)',
}

DEFAULT_HANDLERS = {'keys': 'default_handler'}
DEFAULT_FORMATTERS = {'keys': 'file,syslog'}
DEFAULT_FORMATTER_FILE = {
    'format': 'OSPD['
    + str(os.getpid())
    + '] %(asctime)s: %(levelname)s: (%(name)s) %(message)s',
    'datefmt': '',
}
DEFAULT_FORMATTER_SYSLOG = {
    'format': 'OSPD['
    + str(os.getpid())
    + '] %(levelname)s: (%(name)s) %(message)s',
    'datefmt': '',
}
DEFAULT_LOGGERS = {'keys': 'root'}
DEFAULT_ROOT_LOGGER = {
    'level': 'NOTSET',
    'handlers': 'default_handler',
    'propagate': '0',
}


def init_logging(
    log_level: int,
    *,
    log_file: Optional[str] = None,
    log_config: Optional[str] = None,
    foreground: Optional[bool] = False,
):
    config = configparser.ConfigParser()
    config['handlers'] = DEFAULT_HANDLERS
    config['formatters'] = DEFAULT_FORMATTERS
    config['formatter_file'] = DEFAULT_FORMATTER_FILE
    config['formatter_syslog'] = DEFAULT_FORMATTER_SYSLOG

    if foreground:
        config['handler_default_handler'] = DEFAULT_HANDLER_CONSOLE
    elif log_file:
        config['handler_default_handler'] = DEFAULT_HANDLER_FILE
        config['handler_default_handler']['args'] = "('" + log_file + "', 'a')"
    else:
        config['handler_default_handler'] = DEFAULT_HANDLER_SYSLOG

    config['handler_default_handler']['level'] = log_level
    log_config_path = Path(log_config)
    if log_config_path.exists():
        config.read(log_config)
    else:
        config['loggers'] = DEFAULT_LOGGERS
        config['logger_root'] = DEFAULT_ROOT_LOGGER

    fileConfig(config, disable_existing_loggers=False)
    logging.getLogger()
