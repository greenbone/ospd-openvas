# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from typing import Optional, Dict, Any

import logging
import subprocess
import psutil


logger = logging.getLogger(__name__)

_BOOL_DICT = {'no': 0, 'yes': 1}


class NASLCli:
    """Class for calling nasl-cli executable"""

    @staticmethod
    def load_vts_into_redis() -> bool:
        """Loads all VTs into the redis database"""
        try:
            subprocess.check_call(
                ['nasl-cli', 'feed', 'update'], stdout=subprocess.DEVNULL
            )
            return True
        except (subprocess.SubprocessError, OSError) as err:
            logger.error('nasl-cli failed to load VTs. %s', err)
            return False


class Openvas:
    """Class for calling the openvas executable"""

    @staticmethod
    def _get_version_output() -> Optional[str]:
        try:
            result = subprocess.check_output(
                ['openvas', '-V'], stderr=subprocess.STDOUT
            )
            return result.decode('ascii')
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug(
                'Is was not possible to call openvas to get the version '
                'information. Reason %s',
                e,
            )
            return None

    @staticmethod
    def check() -> bool:
        """Checks that openvas command line tool is found and
        is executable.
        """
        try:
            subprocess.check_call(['openvas', '-V'], stdout=subprocess.DEVNULL)
            return True
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug(
                'It was not possible to call the openvas executable. Reason %s',
                e,
            )
            return False

    @staticmethod
    def check_sudo() -> bool:
        """Checks if openvas can be run with sudo"""
        try:
            subprocess.check_call(
                ['sudo', '-n', 'openvas', '-s'], stdout=subprocess.DEVNULL
            )
            return True
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug(
                'It was not possible to call openvas with sudo. '
                'The scanner will run as non-root user. Reason %s',
                e,
            )
            return False

    @classmethod
    def get_version(cls) -> Optional[str]:
        """Returns the version string of the openvas executable"""
        result = cls._get_version_output()

        if result is None:
            return None

        version = result.split('\n')
        if version[0].find('OpenVAS') < 0:
            return None

        return version[0]

    @staticmethod
    def get_settings() -> Dict[str, Any]:
        """Parses the current settings of the openvas executable"""
        param_list = dict()

        try:
            result = subprocess.check_output(['openvas', '-s'])
            result = result.decode('ascii')
        except (subprocess.SubprocessError, OSError, UnicodeDecodeError) as e:
            logger.warning('Could not gather openvas settings. Reason %s', e)
            return param_list

        for conf in result.split('\n'):
            if not conf:
                continue

            try:
                key, value = conf.split('=', 1)
            except ValueError:
                logger.warning("Could not parse openvas setting '%s'", conf)
                continue

            key = key.strip()
            value = value.strip()

            if value:
                value = _BOOL_DICT.get(value, value)
                param_list[key] = value

        return param_list

    @staticmethod
    def load_vts_into_redis() -> bool:
        """Loads all VTs into the redis database"""
        logger.debug('Loading VTs into Redis DB...')

        try:
            subprocess.check_call(
                ['openvas', '--update-vt-info'], stdout=subprocess.DEVNULL
            )
            logger.debug('Finished loading VTs into Redis DB')
            return True
        except (subprocess.SubprocessError, OSError) as err:
            logger.error('OpenVAS Scanner failed to load VTs. %s', err)
            return False

    @staticmethod
    def start_scan(
        scan_id: str,
        sudo: bool = False,
        niceness: int = None,
    ) -> Optional[psutil.Popen]:
        """Calls openvas to start a scan process"""
        cmd = []

        if niceness:
            cmd += ['nice', '-n', niceness]
            logger.debug("Starting scan with niceness %s", niceness)

        if sudo:
            cmd += ['sudo', '-n']

        cmd += ['openvas', '--scan-start', scan_id]

        try:
            return psutil.Popen(cmd, shell=False)
        except (psutil.Error, OSError, FileNotFoundError) as e:
            # the command is not available
            logger.warning("Could not start scan process. Reason %s", e)
            return None

    @staticmethod
    def stop_scan(scan_id: str, sudo: bool = False) -> bool:
        """Calls openvas to stop a scan process"""
        cmd = []

        if sudo:
            cmd += ['sudo', '-n']

        cmd += ['openvas', '--scan-stop', scan_id]

        try:
            subprocess.check_call(cmd)
            return True
        except (subprocess.SubprocessError, OSError) as e:
            # the command is not available
            logger.warning(
                'Not possible to stop scan: %s. Reason %s',
                scan_id,
                e,
            )
            return False
