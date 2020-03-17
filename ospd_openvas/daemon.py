# -*- coding: utf-8 -*-
# Copyright (C) 2019 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

# pylint: disable=too-many-lines

""" Setup for the OSP OpenVAS Server. """

import logging
import time
import uuid
import binascii
import copy

from typing import Optional, Dict, List, Tuple, Iterator
from datetime import datetime
from base64 import b64decode

from pathlib import Path
from os import geteuid
from lxml.etree import tostring, SubElement, Element

import psutil

from ospd.errors import OspdError
from ospd.ospd import OSPDaemon
from ospd.server import BaseServer
from ospd.main import main as daemon_main
from ospd.cvss import CVSS
from ospd.vtfilter import VtsFilter

from ospd_openvas import __version__
from ospd_openvas.errors import OspdOpenvasError

from ospd_openvas.nvticache import NVTICache
from ospd_openvas.db import MainDB, BaseDB, ScanDB
from ospd_openvas.lock import LockFile
from ospd_openvas.preferencehandler import PreferenceHandler, _from_bool_to_str
from ospd_openvas.openvas import Openvas

logger = logging.getLogger(__name__)


OSPD_DESC = """
This scanner runs OpenVAS to scan the target hosts.

OpenVAS (Open Vulnerability Assessment Scanner) is a powerful scanner
for vulnerabilities in IT infrastrucutres. The capabilities include
unauthenticated scanning as well as authenticated scanning for
various types of systems and services.

For more details about OpenVAS see:
http://www.openvas.org/

The current version of ospd-openvas is a simple frame, which sends
the server parameters to the Greenbone Vulnerability Manager daemon (GVMd) and
checks the existence of OpenVAS binary. But it can not run scans yet.
"""

OSPD_PARAMS = {
    'auto_enable_dependencies': {
        'type': 'boolean',
        'name': 'auto_enable_dependencies',
        'default': 1,
        'mandatory': 1,
        'description': 'Automatically enable the plugins that are depended on',
    },
    'cgi_path': {
        'type': 'string',
        'name': 'cgi_path',
        'default': '/cgi-bin:/scripts',
        'mandatory': 1,
        'description': 'Look for default CGIs in /cgi-bin and /scripts',
    },
    'checks_read_timeout': {
        'type': 'integer',
        'name': 'checks_read_timeout',
        'default': 5,
        'mandatory': 1,
        'description': (
            'Number  of seconds that the security checks will '
            + 'wait for when doing a recv()'
        ),
    },
    'drop_privileges': {
        'type': 'boolean',
        'name': 'drop_privileges',
        'default': 0,
        'mandatory': 1,
        'description': '',
    },
    'network_scan': {
        'type': 'boolean',
        'name': 'network_scan',
        'default': 0,
        'mandatory': 1,
        'description': '',
    },
    'non_simult_ports': {
        'type': 'string',
        'name': 'non_simult_ports',
        'default': '139, 445, 3389, Services/irc',
        'mandatory': 1,
        'description': (
            'Prevent to make two connections on the same given '
            + 'ports at the same time.'
        ),
    },
    'open_sock_max_attempts': {
        'type': 'integer',
        'name': 'open_sock_max_attempts',
        'default': 5,
        'mandatory': 0,
        'description': (
            'Number of unsuccessful retries to open the socket '
            + 'before to set the port as closed.'
        ),
    },
    'timeout_retry': {
        'type': 'integer',
        'name': 'timeout_retry',
        'default': 5,
        'mandatory': 0,
        'description': (
            'Number of retries when a socket connection attempt ' + 'timesout.'
        ),
    },
    'optimize_test': {
        'type': 'integer',
        'name': 'optimize_test',
        'default': 5,
        'mandatory': 0,
        'description': (
            'By default, openvas does not trust the remote ' + 'host banners.'
        ),
    },
    'plugins_timeout': {
        'type': 'integer',
        'name': 'plugins_timeout',
        'default': 5,
        'mandatory': 0,
        'description': 'This is the maximum lifetime, in seconds of a plugin.',
    },
    'report_host_details': {
        'type': 'boolean',
        'name': 'report_host_details',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'safe_checks': {
        'type': 'boolean',
        'name': 'safe_checks',
        'default': 1,
        'mandatory': 1,
        'description': (
            'Disable the plugins with potential to crash '
            + 'the remote services'
        ),
    },
    'scanner_plugins_timeout': {
        'type': 'integer',
        'name': 'scanner_plugins_timeout',
        'default': 36000,
        'mandatory': 1,
        'description': 'Like plugins_timeout, but for ACT_SCANNER plugins.',
    },
    'time_between_request': {
        'type': 'integer',
        'name': 'time_between_request',
        'default': 0,
        'mandatory': 0,
        'description': (
            'Allow to set a wait time between two actions '
            + '(open, send, close).'
        ),
    },
    'unscanned_closed': {
        'type': 'boolean',
        'name': 'unscanned_closed',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'unscanned_closed_udp': {
        'type': 'boolean',
        'name': 'unscanned_closed_udp',
        'default': 1,
        'mandatory': 1,
        'description': '',
    },
    'expand_vhosts': {
        'type': 'boolean',
        'name': 'expand_vhosts',
        'default': 1,
        'mandatory': 0,
        'description': 'Whether to expand the target hosts '
        + 'list of vhosts with values gathered from sources '
        + 'such as reverse-lookup queries and VT checks '
        + 'for SSL/TLS certificates.',
    },
    'test_empty_vhost': {
        'type': 'boolean',
        'name': 'test_empty_vhost',
        'default': 0,
        'mandatory': 0,
        'description': 'If  set  to  yes, the scanner will '
        + 'also test the target by using empty vhost value '
        + 'in addition to the targets associated vhost values.',
    },
}

OID_SSH_AUTH = "1.3.6.1.4.1.25623.1.0.103591"
OID_SMB_AUTH = "1.3.6.1.4.1.25623.1.0.90023"
OID_ESXI_AUTH = "1.3.6.1.4.1.25623.1.0.105058"
OID_SNMP_AUTH = "1.3.6.1.4.1.25623.1.0.105076"


def safe_int(value: str) -> Optional[int]:
    """ Convert a sring into an integer and return None in case of errors during
    conversion
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


class OpenVasVtsFilter(VtsFilter):
    """ Methods to overwrite the ones in the original class.
    Each method formats the value to be compatible with the filter
    """

    def format_vt_modification_time(self, value: str) -> str:
        """ Convert the string seconds since epoch into a 19 character
        string representing YearMonthDayHourMinuteSecond,
        e.g. 20190319122532. This always refers to UTC.
        """

        return datetime.utcfromtimestamp(int(value)).strftime("%Y%m%d%H%M%S")


class OSPDopenvas(OSPDaemon):

    """ Class for ospd-openvas daemon. """

    def __init__(
        self, *, niceness=None, lock_file_dir='/var/run/ospd', **kwargs
    ):
        """ Initializes the ospd-openvas daemon's internal data. """

        super().__init__(customvtfilter=OpenVasVtsFilter(), **kwargs)

        self.server_version = __version__

        self._niceness = str(niceness)

        self.feed_lock = LockFile(Path(lock_file_dir) / 'feed-update.lock')
        self.daemon_info['name'] = 'OSPd OpenVAS'
        self.scanner_info['name'] = 'openvas'
        self.scanner_info['version'] = ''  # achieved during self.init()
        self.scanner_info['description'] = OSPD_DESC

        for name, param in OSPD_PARAMS.items():
            self.set_scanner_param(name, param)

        self._sudo_available = None
        self._is_running_as_root = None

        self.scan_only_params = dict()

        self.main_kbindex = None

        self.main_db = MainDB()

        self.nvti = NVTICache(self.main_db)

        self.pending_feed = None

        self.temp_vts = None

    def init(self, server: BaseServer) -> None:

        server.start(self.handle_client_stream)

        self.scanner_info['version'] = Openvas.get_version()

        self.set_params_from_openvas_settings()

        if not self.nvti.ctx:
            with self.feed_lock.wait_for_lock():
                Openvas.load_vts_into_redis()

        self.load_vts()

        self.initialized = True

    def set_params_from_openvas_settings(self):
        """ Set OSPD_PARAMS with the params taken from the openvas executable.
        """
        param_list = Openvas.get_settings()

        for elem in param_list:
            if elem not in OSPD_PARAMS:
                self.scan_only_params[elem] = param_list[elem]
            else:
                OSPD_PARAMS[elem]['default'] = param_list[elem]

    def feed_is_outdated(self, current_feed: str) -> Optional[bool]:
        """ Compare the current feed with the one in the disk.

        Return:
            False if there is no new feed.
            True if the feed version in disk is newer than the feed in
                redis cache.
            None if there is no feed on the disk.
        """
        plugins_folder = self.scan_only_params.get('plugins_folder')
        if not plugins_folder:
            raise OspdOpenvasError("Error: Path to plugins folder not found.")

        feed_info_file = Path(plugins_folder) / 'plugin_feed_info.inc'
        if not feed_info_file.exists():
            self.set_params_from_openvas_settings()
            logger.debug('Plugins feed file %s not found.', feed_info_file)
            return None

        current_feed = safe_int(current_feed)

        feed_date = None
        with feed_info_file.open() as fcontent:
            for line in fcontent:
                if "PLUGIN_SET" in line:
                    feed_date = line.split('=', 1)[1]
                    feed_date = feed_date.strip()
                    feed_date = feed_date.replace(';', '')
                    feed_date = feed_date.replace('"', '')
                    feed_date = safe_int(feed_date)
                    break

        logger.debug("Current feed version: %s", current_feed)
        logger.debug("Plugin feed version: %s", feed_date)

        return (
            (not feed_date) or (not current_feed) or (current_feed < feed_date)
        )

    def feed_is_healthy(self):
        """ Compare the amount of filename keys and nvt keys in redis
        with the amount of oid loaded in memory.

        Return:
            True if the count is matching. False on failure.
        """
        filename_count = self.nvti.get_nvt_files_count()
        nvt_count = self.nvti.get_nvt_count()

        return len(self.vts) == filename_count == nvt_count

    def check_feed(self):
        """ Check if there is a feed update.

        Wait until all the running scans finished. Set a flag to announce there
        is a pending feed update, which avoids to start a new scan.
        """
        current_feed = self.nvti.get_feed_version()
        is_outdated = self.feed_is_outdated(current_feed)

        # Check if the feed is already accessible from the disk.
        if current_feed and is_outdated is None:
            self.pending_feed = True
            return

        # Check if the nvticache in redis is outdated
        if not current_feed or is_outdated:
            self.pending_feed = True

            with self.feed_lock as fl:
                if fl.has_lock():
                    Openvas.load_vts_into_redis()
                else:
                    logger.debug(
                        "The feed was not upload or it is outdated, "
                        "but other process is locking the update. "
                        "Trying again later..."
                    )
                    return

        _running_scan = False
        for scan_id in self.scan_processes:
            if self.scan_processes[scan_id].is_alive():
                _running_scan = True

        # Check if the NVT dict is outdated
        if self.pending_feed:
            _pending_feed = True
        else:
            _pending_feed = (
                self.get_vts_version() != self.nvti.get_feed_version()
            )

        _feed_is_healthy = self.feed_is_healthy()
        if _running_scan and not _feed_is_healthy:
            _pending_feed = True

            with self.feed_lock as fl:
                if fl.has_lock():
                    self.nvti.force_reload()
                    Openvas.load_vts_into_redis()
                else:
                    logger.debug(
                        "The VT Cache in memory is not healthy "
                        "and other process is locking the update. "
                        "Trying again later..."
                    )
                    return

        if _running_scan and _pending_feed:
            if not self.pending_feed:
                self.pending_feed = True
                logger.info(
                    'There is a running scan process locking the feed update. '
                    'Therefore the feed update will be performed later.'
                )
        elif (
            _pending_feed
            and not _running_scan
            and not self.feed_lock.is_locked()
        ):
            self.vts.clear()
            self.load_vts()

    def scheduler(self):
        """This method is called periodically to run tasks."""
        self.check_feed()

    def get_single_vt(self, vt_id, oids=None):
        _vt_params = self.nvti.get_nvt_params(vt_id)
        _vt_refs = self.nvti.get_nvt_refs(vt_id)
        _custom = self.nvti.get_nvt_metadata(vt_id)

        _name = _custom.pop('name')
        _vt_creation_time = _custom.pop('creation_date')
        _vt_modification_time = _custom.pop('last_modification')

        if oids:
            _vt_dependencies = list()
            if 'dependencies' in _custom:
                _deps = _custom.pop('dependencies')
                _deps_list = _deps.split(', ')
                for dep in _deps_list:
                    _vt_dependencies.append(oids.get('filename:' + dep))
        else:
            _vt_dependencies = None

        _summary = None
        _impact = None
        _affected = None
        _insight = None
        _solution = None
        _solution_t = None
        _vuldetect = None
        _qod_t = None
        _qod_v = None

        if 'summary' in _custom:
            _summary = _custom.pop('summary')
        if 'impact' in _custom:
            _impact = _custom.pop('impact')
        if 'affected' in _custom:
            _affected = _custom.pop('affected')
        if 'insight' in _custom:
            _insight = _custom.pop('insight')
        if 'solution' in _custom:
            _solution = _custom.pop('solution')
            if 'solution_type' in _custom:
                _solution_t = _custom.pop('solution_type')

        if 'vuldetect' in _custom:
            _vuldetect = _custom.pop('vuldetect')
        if 'qod_type' in _custom:
            _qod_t = _custom.pop('qod_type')
        elif 'qod' in _custom:
            _qod_v = _custom.pop('qod')

        _severity = dict()
        if 'severity_base_vector' in _custom:
            _severity_vector = _custom.pop('severity_base_vector')
        else:
            _severity_vector = _custom.pop('cvss_base_vector')
        _severity['severity_base_vector'] = _severity_vector
        if 'severity_type' in _custom:
            _severity_type = _custom.pop('severity_type')
        else:
            _severity_type = 'cvss_base_v2'
        _severity['severity_type'] = _severity_type
        if 'severity_origin' in _custom:
            _severity['severity_origin'] = _custom.pop('severity_origin')

        if _name is None:
            _name = ''

        vt = {'name': _name}
        if _custom is not None:
            vt["custom"] = _custom
        if _vt_params is not None:
            vt["vt_params"] = _vt_params
        if _vt_refs is not None:
            vt["vt_refs"] = _vt_refs
        if _vt_dependencies is not None:
            vt["vt_dependencies"] = _vt_dependencies
        if _vt_creation_time is not None:
            vt["creation_time"] = _vt_creation_time
        if _vt_modification_time is not None:
            vt["modification_time"] = _vt_modification_time
        if _summary is not None:
            vt["summary"] = _summary
        if _impact is not None:
            vt["impact"] = _impact
        if _affected is not None:
            vt["affected"] = _affected
        if _insight is not None:
            vt["insight"] = _insight

        if _solution is not None:
            vt["solution"] = _solution
            if _solution_t is not None:
                vt["solution_type"] = _solution_t

        if _vuldetect is not None:
            vt["detection"] = _vuldetect

        if _qod_t is not None:
            vt["qod_type"] = _qod_t
        elif _qod_v is not None:
            vt["qod"] = _qod_v

        if _severity is not None:
            vt["severities"] = _severity

        return vt

    def get_vt_iterator(
        self, vt_selection: List[str] = None, details: bool = True
    ) -> Iterator[Tuple[str, Dict]]:
        """ Yield the vts from the Redis NVTicache. """

        oids = None
        if details:
            oids = dict(self.nvti.get_oids())

        for vt_id in vt_selection:
            vt = self.get_single_vt(vt_id, oids)
            yield (vt_id, vt)

    def load_vts(self):
        """ Load the VT's metadata into the vts global dictionary. """

        with self.feed_lock as fl:
            if not fl.has_lock():
                logger.warning(
                    'Error acquiring feed lock. Trying again later...'
                )
                return

            self.initialized = False
            logger.info('Loading VTs in memory.')

            oids = dict(self.nvti.get_oids())

            logger.debug('Found %s NVTs in redis.', len(oids))

            for _, vt_id in oids.items():
                vt = self.get_single_vt(vt_id, oids)

                if (
                    not vt
                    or vt.get('vt_params') is None
                    or vt.get('custom') is None
                ):
                    logger.warning(
                        'Error loading VTs in memory. Trying again later...'
                    )
                    return

                custom = {'family': vt['custom'].get('family')}
                try:
                    self.add_vt(
                        vt_id,
                        name=vt.get('name'),
                        qod_t=vt.get('qod_type'),
                        qod_v=vt.get('qod'),
                        severities=vt.get('severities'),
                        vt_modification_time=vt.get('modification_time'),
                        vt_params=vt.get('vt_params'),
                        custom=custom,
                    )
                except OspdError as e:
                    logger.warning("Error while adding VT %s. %s", vt_id, e)

            _feed_version = self.nvti.get_feed_version()

            self.set_vts_version(vts_version=_feed_version)
            self.vts.calculate_vts_collection_hash()
            self.pending_feed = False
            self.initialized = True

            logger.info('Finish loading up vts.')

            logger.debug('Loaded %s vts.', len(self.vts))

    @staticmethod
    def get_custom_vt_as_xml_str(vt_id: str, custom: Dict) -> str:
        """ Return an xml element with custom metadata formatted as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            custom: Dictionary with the custom metadata.
        Return:
            Xml element as string.
        """

        _custom = Element('custom')
        for key, val in custom.items():
            xml_key = SubElement(_custom, key)
            try:
                xml_key.text = val
            except ValueError as e:
                logger.warning(
                    "Not possible to parse custom tag for VT %s: %s", vt_id, e
                )
        return tostring(_custom).decode('utf-8')

    @staticmethod
    def get_severities_vt_as_xml_str(vt_id: str, severities: Dict) -> str:
        """ Return an xml element with severities as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            severities: Dictionary with the severities.
        Return:
            Xml element as string.
        """
        _severities = Element('severities')
        _severity = SubElement(_severities, 'severity')
        if 'severity_base_vector' in severities:
            try:
                _severity.text = severities.get('severity_base_vector')
            except ValueError as e:
                logger.warning(
                    "Not possible to parse severity tag for vt %s: %s", vt_id, e
                )
        if 'severity_origin' in severities:
            _severity.set('origin', severities.get('severity_origin'))
        if 'severity_type' in severities:
            _severity.set('type', severities.get('severity_type'))

        return tostring(_severities).decode('utf-8')

    @staticmethod
    def get_params_vt_as_xml_str(vt_id: str, vt_params: Dict) -> str:
        """ Return an xml element with params formatted as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_params: Dictionary with the VT parameters.
        Return:
            Xml element as string.
        """
        vt_params_xml = Element('params')
        for _pref_id, prefs in vt_params.items():
            vt_param = Element('param')
            vt_param.set('type', prefs['type'])
            vt_param.set('id', _pref_id)
            xml_name = SubElement(vt_param, 'name')
            try:
                xml_name.text = prefs['name']
            except ValueError as e:
                logger.warning(
                    "Not possible to parse parameter for VT %s: %s", vt_id, e
                )
            if prefs['default']:
                xml_def = SubElement(vt_param, 'default')
                try:
                    xml_def.text = prefs['default']
                except ValueError as e:
                    logger.warning(
                        "Not possible to parse default parameter for VT %s: %s",
                        vt_id,
                        e,
                    )
            vt_params_xml.append(vt_param)

        return tostring(vt_params_xml).decode('utf-8')

    @staticmethod
    def get_refs_vt_as_xml_str(vt_id: str, vt_refs: Dict) -> str:
        """ Return an xml element with references formatted as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_refs: Dictionary with the VT references.
        Return:
            Xml element as string.
        """
        vt_refs_xml = Element('refs')
        for ref_type, ref_values in vt_refs.items():
            for value in ref_values:
                vt_ref = Element('ref')
                if ref_type == "xref" and value:
                    for xref in value.split(', '):
                        try:
                            _type, _id = xref.split(':', 1)
                        except ValueError:
                            logger.error(
                                'Not possible to parse xref %s for VT %s',
                                xref,
                                vt_id,
                            )
                            continue
                        vt_ref.set('type', _type.lower())
                        vt_ref.set('id', _id)
                elif value:
                    vt_ref.set('type', ref_type.lower())
                    vt_ref.set('id', value)
                else:
                    continue
                vt_refs_xml.append(vt_ref)

        return tostring(vt_refs_xml).decode('utf-8')

    @staticmethod
    def get_dependencies_vt_as_xml_str(
        vt_id: str, vt_dependencies: List
    ) -> str:
        """ Return  an xml element with dependencies as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_dependencies: List with the VT dependencies.
        Return:
            Xml element as string.
        """
        vt_deps_xml = Element('dependencies')
        for dep in vt_dependencies:
            _vt_dep = Element('dependency')
            try:
                _vt_dep.set('vt_id', dep)
            except (ValueError, TypeError):
                logger.error(
                    'Not possible to add dependency %s for VT %s', dep, vt_id
                )
                continue
            vt_deps_xml.append(_vt_dep)

        return tostring(vt_deps_xml).decode('utf-8')

    @staticmethod
    def get_creation_time_vt_as_xml_str(
        vt_id: str, vt_creation_time: str
    ) -> str:
        """ Return creation time as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_creation_time: String with the VT creation time.
        Return:
           Xml element as string.
        """
        _time = Element('creation_time')
        try:
            _time.text = vt_creation_time
        except ValueError as e:
            logger.warning(
                "Not possible to parse creation time for VT %s: %s", vt_id, e
            )
        return tostring(_time).decode('utf-8')

    @staticmethod
    def get_modification_time_vt_as_xml_str(
        vt_id: str, vt_modification_time: str
    ) -> str:
        """ Return modification time as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_modification_time: String with the VT modification time.
        Return:
            Xml element as string.
        """
        _time = Element('modification_time')
        try:
            _time.text = vt_modification_time
        except ValueError as e:
            logger.warning(
                "Not possible to parse modification time for VT %s: %s",
                vt_id,
                e,
            )
        return tostring(_time).decode('utf-8')

    @staticmethod
    def get_summary_vt_as_xml_str(vt_id: str, summary: str) -> str:
        """ Return summary as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            summary: String with a VT summary.
        Return:
            Xml element as string.
        """
        _summary = Element('summary')
        try:
            _summary.text = summary
        except ValueError as e:
            logger.warning(
                "Not possible to parse summary tag for VT %s: %s", vt_id, e
            )
        return tostring(_summary).decode('utf-8')

    @staticmethod
    def get_impact_vt_as_xml_str(vt_id: str, impact) -> str:
        """ Return impact as string.

        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            impact (str): String which explain the vulneravility impact.
        Return:
            string: xml element as string.
        """
        _impact = Element('impact')
        try:
            _impact.text = impact
        except ValueError as e:
            logger.warning(
                "Not possible to parse impact tag for VT %s: %s", vt_id, e
            )
        return tostring(_impact).decode('utf-8')

    @staticmethod
    def get_affected_vt_as_xml_str(vt_id: str, affected: str) -> str:
        """ Return affected as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            affected: String which explain what is affected.
        Return:
            Xml element as string.
        """
        _affected = Element('affected')
        try:
            _affected.text = affected
        except ValueError as e:
            logger.warning(
                "Not possible to parse affected tag for VT %s: %s", vt_id, e
            )
        return tostring(_affected).decode('utf-8')

    @staticmethod
    def get_insight_vt_as_xml_str(vt_id: str, insight: str) -> str:
        """ Return insight as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            insight: String giving an insight of the vulnerability.
        Return:
            Xml element as string.
        """
        _insight = Element('insight')
        try:
            _insight.text = insight
        except ValueError as e:
            logger.warning(
                "Not possible to parse insight tag for VT %s: %s", vt_id, e
            )
        return tostring(_insight).decode('utf-8')

    @staticmethod
    def get_solution_vt_as_xml_str(
        vt_id: str,
        solution: str,
        solution_type: Optional[str] = None,
        solution_method: Optional[str] = None,
    ) -> str:
        """ Return solution as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            solution: String giving a possible solution.
            solution_type: A solution type
            solution_method: A solution method
        Return:
            Xml element as string.
        """
        _solution = Element('solution')
        try:
            _solution.text = solution
        except ValueError as e:
            logger.warning(
                "Not possible to parse solution tag for VT %s: %s", vt_id, e
            )
        if solution_type:
            _solution.set('type', solution_type)
        if solution_method:
            _solution.set('method', solution_method)
        return tostring(_solution).decode('utf-8')

    @staticmethod
    def get_detection_vt_as_xml_str(
        vt_id: str,
        detection: Optional[str] = None,
        qod_type: Optional[str] = None,
        qod: Optional[str] = None,
    ) -> str:
        """ Return detection as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            detection: String which explain how the vulnerability
              was detected.
            qod_type: qod type.
            qod: qod value.
        Return:
            Xml element as string.
        """
        _detection = Element('detection')
        if detection:
            try:
                _detection.text = detection
            except ValueError as e:
                logger.warning(
                    "Not possible to parse detection tag for VT %s: %s",
                    vt_id,
                    e,
                )
        if qod_type:
            _detection.set('qod_type', qod_type)
        elif qod:
            _detection.set('qod', qod)

        return tostring(_detection).decode('utf-8')

    @property
    def is_running_as_root(self) -> bool:
        """ Check if it is running as root user."""
        if self._is_running_as_root is not None:
            return self._is_running_as_root

        self._is_running_as_root = False
        if geteuid() == 0:
            self._is_running_as_root = True

        return self._is_running_as_root

    @property
    def sudo_available(self) -> bool:
        """ Checks that sudo is available """
        if self._sudo_available is not None:
            return self._sudo_available

        if self.is_running_as_root:
            self._sudo_available = False
            return self._sudo_available

        self._sudo_available = Openvas.check_sudo()

        return self._sudo_available

    def check(self) -> bool:
        """ Checks that openvas command line tool is found and
        is executable. """
        has_openvas = Openvas.check()
        if not has_openvas:
            logger.error(
                'openvas executable not available. Please install openvas'
                ' into your PATH.'
            )
        return has_openvas

    def update_progress(self, scan_id: str, current_host: str, msg: str):
        """ Calculate percentage and update the scan status of a host
        for the progress bar.
        Arguments:
            scan_id: Scan ID to identify the current scan process.
            current_host: Host in the target to be updated.
            msg: String with launched and total plugins.
        """
        try:
            launched, total = msg.split('/')
        except ValueError:
            return
        if float(total) == 0:
            return
        elif float(total) == -1:
            host_prog = 100
        else:
            host_prog = (float(launched) / float(total)) * 100
        self.set_scan_host_progress(scan_id, current_host, host_prog)

    def report_openvas_scan_status(
        self, scan_db: ScanDB, scan_id: str, current_host: str
    ):
        """ Get all status entries from redis kb.

        Arguments:
            scan_id: Scan ID to identify the current scan.
            current_host: Host to be updated.
        """
        res = scan_db.get_scan_status()
        while res:
            self.update_progress(scan_id, current_host, res)
            res = scan_db.get_scan_status()

    def get_severity_score(self, vt_aux: dict) -> Optional[float]:
        """ Return the severity score for the given oid.
        Arguments:
            vt_aux: VT element from which to get the severity vector
        Returns:
            The calculated cvss base value. None if there is no severity
            vector or severity type is not cvss base version 2.
        """
        if vt_aux:
            severity_type = vt_aux['severities'].get('severity_type')
            severity_vector = vt_aux['severities'].get('severity_base_vector')

            if severity_type == "cvss_base_v2" and severity_vector:
                return CVSS.cvss_base_v2_value(severity_vector)

        return None

    def report_openvas_results(
        self, db: BaseDB, scan_id: str, current_host: str
    ):
        """ Get all result entries from redis kb. """
        res = db.get_result()
        while res:
            msg = res.split('|||')
            roid = msg[3].strip()
            rqod = ''
            rname = ''
            rhostname = msg[1].strip() if msg[1] else ''
            host_is_dead = "Host dead" in msg[4]
            vt_aux = None

            if roid and not host_is_dead:
                vt_aux = copy.deepcopy(self.vts.get(roid))

            if not vt_aux and not host_is_dead:
                logger.warning('Invalid VT oid %s for a result', roid)

            if vt_aux:
                if vt_aux.get('qod_type'):
                    qod_t = vt_aux.get('qod_type')
                    rqod = self.nvti.QOD_TYPES[qod_t]
                elif vt_aux.get('qod'):
                    rqod = vt_aux.get('qod')

                rname = vt_aux.get('name')

            if msg[0] == 'ERRMSG':
                self.add_scan_error(
                    scan_id,
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                    port=msg[2],
                    test_id=roid,
                )

            if msg[0] == 'LOG':
                self.add_scan_log(
                    scan_id,
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                    port=msg[2],
                    qod=rqod,
                    test_id=roid,
                )

            if msg[0] == 'HOST_DETAIL':
                self.add_scan_host_detail(
                    scan_id,
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                )

            if msg[0] == 'ALARM':
                rseverity = self.get_severity_score(vt_aux)
                self.add_scan_alarm(
                    scan_id,
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                    port=msg[2],
                    test_id=roid,
                    severity=rseverity,
                    qod=rqod,
                )

            vt_aux = None
            del vt_aux
            res = db.get_result()

    def report_openvas_timestamp_scan_host(
        self, scan_db: ScanDB, scan_id: str, target: str
    ):
        """ Get start and end timestamp of a host scan from redis kb. """
        timestamp = scan_db.get_host_scan_end_time()
        if timestamp:
            self.add_scan_log(
                scan_id, host=target, name='HOST_END', value=timestamp
            )
            return

        timestamp = scan_db.get_host_scan_start_time()
        if timestamp:
            self.add_scan_log(
                scan_id, host=target, name='HOST_START', value=timestamp
            )
            return

    def stop_scan_cleanup(  # pylint: disable=arguments-differ
        self, global_scan_id: str
    ):
        """ Set a key in redis to indicate the wrapper is stopped.
        It is done through redis because it is a new multiprocess
        instance and it is not possible to reach the variables
        of the grandchild process. Send SIGUSR2 to openvas to stop
        each running scan."""

        openvas_scan_id, kbdb = self.main_db.find_kb_database_by_scan_id(
            global_scan_id
        )
        if kbdb:
            kbdb.stop_scan(openvas_scan_id)
            ovas_pid = kbdb.get_scan_process_id()

            parent = None
            try:
                parent = psutil.Process(int(ovas_pid))
            except psutil.NoSuchProcess:
                logger.debug('Process with pid %s already stopped', ovas_pid)
            except TypeError:
                logger.debug(
                    'Scan with ID %s never started and stopped unexpectedly',
                    openvas_scan_id,
                )

            if parent:
                can_stop_scan = Openvas.stop_scan(
                    openvas_scan_id,
                    not self.is_running_as_root and self.sudo_available,
                )
                if not can_stop_scan:
                    logger.debug(
                        'Not possible to stop scan process: %s.', parent,
                    )
                    return False

                logger.debug('Stopping process: %s', parent)

                while parent:
                    try:
                        parent = psutil.Process(int(ovas_pid))
                    except psutil.NoSuchProcess:
                        parent = None

            for scan_db in kbdb.get_scan_databases():
                self.main_db.release_database(scan_db)

    def get_vts_in_groups(self, filters: List[str]) -> List[str]:
        """ Return a list of vts which match with the given filter.

        Arguments:
            filters A list of filters. Each filter has key, operator and
                    a value. They are separated by a space.
                    Supported keys: family

        Returns a list of vt oids which match with the given filter.
        """
        vts_list = list()
        families = dict()

        for oid in self.temp_vts:
            family = self.temp_vts[oid]['custom'].get('family')
            if family not in families:
                families[family] = list()

            families[family].append(oid)

        for elem in filters:
            key, value = elem.split('=')
            if key == 'family' and value in families:
                vts_list.extend(families[value])

        return vts_list

    def get_vt_param_type(self, vtid: str, vt_param_id: str) -> Optional[str]:
        """ Return the type of the vt parameter from the vts dictionary. """

        vt_params_list = self.temp_vts[vtid].get("vt_params")
        if vt_params_list.get(vt_param_id):
            return vt_params_list[vt_param_id]["type"]
        return None

    def get_vt_param_name(self, vtid: str, vt_param_id: str) -> Optional[str]:
        """ Return the type of the vt parameter from the vts dictionary. """

        vt_params_list = self.temp_vts[vtid].get("vt_params")
        if vt_params_list.get(vt_param_id):
            return vt_params_list[vt_param_id]["name"]
        return None

    @staticmethod
    def check_param_type(vt_param_value: str, param_type: str) -> Optional[int]:
        """ Check if the value of a vt parameter matches with
        the type founded.
        """
        if param_type in [
            'entry',
            'password',
            'radio',
            'sshlogin',
        ] and isinstance(vt_param_value, str):
            return None
        elif param_type == 'checkbox' and (
            vt_param_value == '0' or vt_param_value == '1'
        ):
            return None
        elif param_type == 'file':
            try:
                b64decode(vt_param_value.encode())
            except (binascii.Error, AttributeError, TypeError):
                return 1
            return None
        elif param_type == 'integer':
            try:
                int(vt_param_value)
            except ValueError:
                return 1
            return None

        return 1

    @staticmethod
    def build_credentials_as_prefs(credentials: Dict) -> List[str]:
        """ Parse the credential dictionary.
        @param credentials: Dictionary with the credentials.

        @return A list with the credentials in string format to be
                added to the redis KB.
        """
        cred_prefs_list = []
        for credential in credentials.items():
            service = credential[0]
            cred_params = credentials.get(service)
            cred_type = cred_params.get('type', '')
            username = cred_params.get('username', '')
            password = cred_params.get('password', '')

            if service == 'ssh':
                port = cred_params.get('port', '')
                cred_prefs_list.append('auth_port_ssh|||' + '{0}'.format(port))
                cred_prefs_list.append(
                    OID_SSH_AUTH
                    + ':1:'
                    + 'entry:SSH login '
                    + 'name:|||{0}'.format(username)
                )
                if cred_type == 'up':
                    cred_prefs_list.append(
                        OID_SSH_AUTH
                        + ':3:'
                        + 'password:SSH password '
                        + '(unsafe!):|||{0}'.format(password)
                    )
                else:
                    private = cred_params.get('private', '')
                    cred_prefs_list.append(
                        OID_SSH_AUTH
                        + ':2:'
                        + 'password:SSH key passphrase:|||'
                        + '{0}'.format(password)
                    )
                    cred_prefs_list.append(
                        OID_SSH_AUTH
                        + ':4:'
                        + 'file:SSH private key:|||'
                        + '{0}'.format(private)
                    )
            if service == 'smb':
                cred_prefs_list.append(
                    OID_SMB_AUTH
                    + ':1:entry'
                    + ':SMB login:|||{0}'.format(username)
                )
                cred_prefs_list.append(
                    OID_SMB_AUTH
                    + ':2:'
                    + 'password:SMB password:|||'
                    + '{0}'.format(password)
                )
            if service == 'esxi':
                cred_prefs_list.append(
                    OID_ESXI_AUTH
                    + ':1:entry:'
                    + 'ESXi login name:|||'
                    + '{0}'.format(username)
                )
                cred_prefs_list.append(
                    OID_ESXI_AUTH
                    + ':2:'
                    + 'password:ESXi login password:|||'
                    + '{0}'.format(password)
                )

            if service == 'snmp':
                community = cred_params.get('community', '')
                auth_algorithm = cred_params.get('auth_algorithm', '')
                privacy_password = cred_params.get('privacy_password', '')
                privacy_algorithm = cred_params.get('privacy_algorithm', '')

                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':1:'
                    + 'password:SNMP Community:|||'
                    + '{0}'.format(community)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':2:'
                    + 'entry:SNMPv3 Username:|||'
                    + '{0}'.format(username)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH + ':3:'
                    'password:SNMPv3 Password:|||' + '{0}'.format(password)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':4:'
                    + 'radio:SNMPv3 Authentication Algorithm:|||'
                    + '{0}'.format(auth_algorithm)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':5:'
                    + 'password:SNMPv3 Privacy Password:|||'
                    + '{0}'.format(privacy_password)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':6:'
                    + 'radio:SNMPv3 Privacy Algorithm:|||'
                    + '{0}'.format(privacy_algorithm)
                )

        return cred_prefs_list

    def exec_scan(self, scan_id: str):
        """ Starts the OpenVAS scanner for scan_id scan. """
        target = self.get_scan_host(scan_id)
        if self.pending_feed:
            logger.info(
                '%s: There is a pending feed update. '
                'The scan can not be started.',
                scan_id,
            )
            self.add_scan_error(
                scan_id,
                name='',
                host=target,
                value=(
                    'It was not possible to start the scan,'
                    'because a pending feed update. Please try later'
                ),
            )
            return 2

        kbdb = self.main_db.get_new_kb_database()
        self.main_kbindex = kbdb.index

        scan_prefs = PreferenceHandler(scan_id, kbdb, self.scan_collection)

        ports = self.get_scan_ports(scan_id)
        if not ports:
            self.add_scan_error(
                scan_id, name='', host=target, value='No port list defined.'
            )
            return 2

        # Get scan options
        options = self.get_scan_options(scan_id)
        prefs_val = []

        exclude_hosts = self.get_scan_exclude_hosts(scan_id)
        if exclude_hosts:
            options['exclude_hosts'] = exclude_hosts

        # Get unfinished hosts, in case it is a resumed scan. And added
        # into exclude_hosts scan preference. Set progress for the finished ones
        # to 100%.
        finished_hosts = self.get_scan_finished_hosts(scan_id)
        if finished_hosts:
            if exclude_hosts:
                finished_hosts_str = ','.join(finished_hosts)
                exclude_hosts = exclude_hosts + ',' + finished_hosts_str
                options['exclude_hosts'] = exclude_hosts
            else:
                options['exclude_hosts'] = ','.join(finished_hosts)

        # Set scan preferences
        for key, value in options.items():
            item_type = ''
            if key in OSPD_PARAMS:
                item_type = OSPD_PARAMS[key].get('type')
            if item_type == 'boolean':
                val = _from_bool_to_str(value)
            else:
                val = str(value)
            prefs_val.append(key + "|||" + val)

        kbdb.add_scan_preferences(scan_prefs.openvas_scan_id, prefs_val)

        prefs_val = None

        # Store main_kbindex as global preference
        ov_maindbid = 'ov_maindbid|||%d' % self.main_kbindex
        kbdb.add_scan_preferences(scan_prefs.openvas_scan_id, [ov_maindbid])

        # Set target
        target_aux = 'TARGET|||%s' % target
        kbdb.add_scan_preferences(scan_prefs.openvas_scan_id, [target_aux])

        # Set port range
        port_range = 'port_range|||%s' % ports
        kbdb.add_scan_preferences(scan_prefs.openvas_scan_id, [port_range])

        # If credentials or vts fail, set this variable.
        do_not_launch = False

        # Set credentials
        credentials = self.get_scan_credentials(scan_id)
        if credentials:
            cred_prefs = self.build_credentials_as_prefs(credentials)
            if cred_prefs:
                kbdb.add_scan_preferences(
                    scan_prefs.openvas_scan_id, cred_prefs
                )
            else:
                self.add_scan_error(
                    scan_id, name='', host=target, value='Malformed credential.'
                )
                do_not_launch = True

        # Set plugins to run.
        # Make a deepcopy of the vts dictionary. Otherwise, consulting the
        # DictProxy object of multiprocessing directly is to expensinve
        # (interprocess communication).
        self.temp_vts = self.vts.copy()
        if not scan_prefs.set_plugins(self.temp_vts):
            self.add_scan_error(
                scan_id, name='', host=target, value='No VTS to run.'
            )
            do_not_launch = True

        # Remove list of vts from scan_collection, as it is not necessary anymore.
        self.scan_collection.release_vts_list(scan_id)

        # Release temp vts dict memory.
        self.temp_vts = None

        scan_prefs.set_reverse_lookup_opt()
        scan_prefs.set_alive_test_option()

        target_options = scan_prefs.target_options

        if do_not_launch:
            self.main_db.release_database(kbdb)
            return 2

        result = Openvas.start_scan(
            scan_prefs.openvas_scan_id,
            not self.is_running_as_root and self.sudo_available,
            self._niceness,
        )

        if result is None:
            return False

        ovas_pid = result.pid

        logger.debug('pid = %s', ovas_pid)

        kbdb.add_scan_process_id(ovas_pid)

        # Wait until the scanner starts and loads all the preferences.
        while kbdb.get_status(scan_prefs.openvas_scan_id) == 'new':
            res = result.poll()
            if res and res < 0:
                self.stop_scan_cleanup(scan_id)
                logger.error(
                    'It was not possible run the task %s, since openvas ended '
                    'unexpectedly with errors during launching.',
                    scan_id,
                )
                return 1

            time.sleep(1)

        no_id_found = False
        while True:
            time.sleep(3)
            # Check if the client stopped the whole scan
            if kbdb.scan_is_stopped(scan_prefs.openvas_scan_id):
                return 1

            self.report_openvas_results(kbdb, scan_id, "")

            for scan_db in kbdb.get_scan_databases():

                id_aux = scan_db.get_scan_id()
                if not id_aux:
                    continue

                if id_aux == scan_prefs.openvas_scan_id:
                    no_id_found = False
                    current_host = scan_db.get_host_ip()

                    self.report_openvas_results(scan_db, scan_id, current_host)
                    self.report_openvas_scan_status(
                        scan_db, scan_id, current_host
                    )
                    self.report_openvas_timestamp_scan_host(
                        scan_db, scan_id, current_host
                    )

                    if scan_db.host_is_finished(scan_prefs.openvas_scan_id):
                        self.set_scan_host_finished(scan_id, current_host)
                        self.report_openvas_scan_status(
                            scan_db, scan_id, current_host
                        )
                        self.report_openvas_timestamp_scan_host(
                            scan_db, scan_id, current_host
                        )

                        kbdb.remove_scan_database(scan_db)
                        self.main_db.release_database(scan_db)

            # Scan end. No kb in use for this scan id
            if no_id_found and kbdb.target_is_finished(scan_id):
                break

            no_id_found = True

        # Delete keys from KB related to this scan task.
        self.main_db.release_database(kbdb)


def main():
    """ OSP openvas main function. """
    daemon_main('OSPD - openvas', OSPDopenvas)


if __name__ == '__main__':
    main()
