# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import configparser
import logging
import os
import time
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
    'class': 'handlers.WatchedFileHandler',
    'level': 'INFO',
    'formatter': 'file',
    'args': '("/dev/null", "a")',
}

DEFAULT_HANDLER_SYSLOG = {
    'class': 'handlers.SysLogHandler',
    'level': 'INFO',
    'formatter': 'syslog',
    'args': '("/dev/log", handlers.SysLogHandler.LOG_USER)',
}

DEFAULT_HANDLERS = {'keys': 'console,file,syslog'}
DEFAULT_FORMATTERS = {'keys': 'file,syslog'}
DEFAULT_FORMATTER_FILE = {
    'format': f'OSPD[{os.getpid()}] %(asctime)s: %(levelname)s: '
    '(%(name)s) %(message)s',
    'datefmt': '',
}
DEFAULT_FORMATTER_SYSLOG = {
    'format': f'OSPD[{os.getpid()}] %(levelname)s: (%(name)s) %(message)s',
    'datefmt': '',
}
DEFAULT_LOGGERS = {'keys': 'root'}
DEFAULT_ROOT_LOGGER = {
    'level': 'NOTSET',
    'handlers': 'file',
    'propagate': '0',
}


def init_logging(
    log_level: int,
    *,
    log_file: Optional[str] = None,
    log_config: Optional[str] = None,
    foreground: Optional[bool] = False,
) -> None:
    config = configparser.ConfigParser()
    config['handlers'] = DEFAULT_HANDLERS
    config['formatters'] = DEFAULT_FORMATTERS
    config['formatter_file'] = DEFAULT_FORMATTER_FILE
    config['formatter_syslog'] = DEFAULT_FORMATTER_SYSLOG
    config['handler_console'] = DEFAULT_HANDLER_CONSOLE
    config['handler_syslog'] = DEFAULT_HANDLER_SYSLOG
    config['handler_file'] = DEFAULT_HANDLER_FILE
    config['loggers'] = DEFAULT_LOGGERS
    config['logger_root'] = DEFAULT_ROOT_LOGGER

    if foreground:
        config['logger_root']['handlers'] = 'console'

    if log_file:
        if foreground:
            config['logger_root']['handlers'] = 'console,file'
        else:
            config['logger_root']['handlers'] = 'file'

        config['handler_file']['args'] = f"('{log_file}', 'a')"

    if not foreground and not log_file:
        config['logger_root']['handlers'] = 'syslog'

    config['handler_file']['level'] = log_level
    config['handler_console']['level'] = log_level
    config['handler_syslog']['level'] = log_level

    log_config_path = Path(log_config)

    if log_config_path.exists():
        config.read(log_config)

    fileConfig(config, disable_existing_loggers=False)
    logging.Formatter.converter = time.gmtime
    logging.getLogger()
