# -*- coding: utf-8 -*-
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


# pylint: disable=too-many-lines

""" Setup for the OSP OpenVAS Server. """

import logging
import time
import copy

from typing import Optional, Dict, List, Tuple, Iterator
from datetime import datetime

from pathlib import Path
from os import geteuid
from lxml.etree import tostring, SubElement, Element

import psutil

from ospd.ospd import OSPDaemon
from ospd.scan import ScanProgress
from ospd.server import BaseServer
from ospd.main import main as daemon_main
from ospd.cvss import CVSS
from ospd.vtfilter import VtsFilter
from ospd.resultlist import ResultList

from ospd_openvas import __version__
from ospd_openvas.errors import OspdOpenvasError

from ospd_openvas.nvticache import NVTICache
from ospd_openvas.db import MainDB, BaseDB, ScanDB
from ospd_openvas.lock import LockFile
from ospd_openvas.preferencehandler import PreferenceHandler
from ospd_openvas.openvas import Openvas
from ospd_openvas.vthelper import VtHelper

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
        'visible_for_client': True,
        'description': 'Automatically enable the plugins that are depended on',
    },
    'cgi_path': {
        'type': 'string',
        'name': 'cgi_path',
        'default': '/cgi-bin:/scripts',
        'mandatory': 1,
        'visible_for_client': True,
        'description': 'Look for default CGIs in /cgi-bin and /scripts',
    },
    'checks_read_timeout': {
        'type': 'integer',
        'name': 'checks_read_timeout',
        'default': 5,
        'mandatory': 1,
        'visible_for_client': True,
        'description': (
            'Number  of seconds that the security checks will '
            + 'wait for when doing a recv()'
        ),
    },
    'non_simult_ports': {
        'type': 'string',
        'name': 'non_simult_ports',
        'default': '139, 445, 3389, Services/irc',
        'mandatory': 1,
        'visible_for_client': True,
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
        'visible_for_client': True,
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
        'visible_for_client': True,
        'description': (
            'Number of retries when a socket connection attempt ' + 'timesout.'
        ),
    },
    'optimize_test': {
        'type': 'boolean',
        'name': 'optimize_test',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'By default, optimize_test is enabled which means openvas does '
            + 'trust the remote host banners and is only launching plugins '
            + 'against the services they have been designed to check. '
            + 'For example it will check a web server claiming to be IIS only '
            + 'for IIS related flaws but will skip plugins testing for Apache '
            + 'flaws, and so on. This default behavior is used to optimize '
            + 'the scanning performance and to avoid false positives. '
            + 'If you are not sure that the banners of the remote host '
            + 'have been tampered with, you can disable this option.'
        ),
    },
    'plugins_timeout': {
        'type': 'integer',
        'name': 'plugins_timeout',
        'default': 5,
        'mandatory': 0,
        'visible_for_client': True,
        'description': 'This is the maximum lifetime, in seconds of a plugin.',
    },
    'report_host_details': {
        'type': 'boolean',
        'name': 'report_host_details',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': '',
    },
    'safe_checks': {
        'type': 'boolean',
        'name': 'safe_checks',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
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
        'visible_for_client': True,
        'description': 'Like plugins_timeout, but for ACT_SCANNER plugins.',
    },
    'time_between_request': {
        'type': 'integer',
        'name': 'time_between_request',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': True,
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
        'visible_for_client': True,
        'description': '',
    },
    'unscanned_closed_udp': {
        'type': 'boolean',
        'name': 'unscanned_closed_udp',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': '',
    },
    'expand_vhosts': {
        'type': 'boolean',
        'name': 'expand_vhosts',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
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
        'visible_for_client': True,
        'description': 'If  set  to  yes, the scanner will '
        + 'also test the target by using empty vhost value '
        + 'in addition to the targets associated vhost values.',
    },
    'max_hosts': {
        'type': 'integer',
        'name': 'max_hosts',
        'default': 30,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'The maximum number of hosts to test at the same time which '
            + 'should be given to the client (which can override it). '
            + 'This value must be computed given your bandwidth, '
            + 'the number of hosts you want to test, your amount of '
            + 'memory and the performance of your processor(s).'
        ),
    },
    'max_checks': {
        'type': 'integer',
        'name': 'max_checks',
        'default': 10,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'The number of plugins that will run against each host being '
            + 'tested. Note that the total number of process will be max '
            + 'checks x max_hosts so you need to find a balance between '
            + 'these two options. Note that launching too many plugins at '
            + 'the same time may disable the remote host, either temporarily '
            + '(ie: inetd closes its ports) or definitely (the remote host '
            + 'crash because it is asked to do too many things at the '
            + 'same time), so be careful.'
        ),
    },
    'port_range': {
        'type': 'string',
        'name': 'port_range',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'This is the default range of ports that the scanner plugins will '
            + 'probe. The syntax of this option is flexible, it can be a '
            + 'single range ("1-1500"), several ports ("21,23,80"), several '
            + 'ranges of ports ("1-1500,32000-33000"). Note that you can '
            + 'specify UDP and TCP ports by prefixing each range by T or U. '
            + 'For instance, the following range will make openvas scan UDP '
            + 'ports 1 to 1024 and TCP ports 1 to 65535 : '
            + '"T:1-65535,U:1-1024".'
        ),
    },
    'test_alive_hosts_only': {
        'type': 'boolean',
        'name': 'test_alive_hosts_only',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'If this option is set, openvas will scan the target list for '
            + 'alive hosts in a separate process while only testing those '
            + 'hosts which are identified as alive. This boosts the scan '
            + 'speed of target ranges with a high amount of dead hosts '
            + 'significantly.'
        ),
    },
    'source_iface': {
        'type': 'string',
        'name': 'source_iface',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Name of the network interface that will be used as the source '
            + 'of connections established by openvas. The scan won\'t be '
            + 'launched if the value isn\'t authorized according to '
            + '(sys_)ifaces_allow / (sys_)ifaces_deny if present.'
        ),
    },
    'ifaces_allow': {
        'type': 'string',
        'name': 'ifaces_allow',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of interfaces names that are authorized '
            + 'as source_iface values.'
        ),
    },
    'ifaces_deny': {
        'type': 'string',
        'name': 'ifaces_deny',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of interfaces names that are not '
            + 'authorized as source_iface values.'
        ),
    },
    'hosts_allow': {
        'type': 'string',
        'name': 'hosts_allow',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of the only targets that are authorized '
            + 'to be scanned. Supports the same syntax as the list targets. '
            + 'Both target hostnames and the address to which they resolve '
            + 'are checked. Hostnames in hosts_allow list are not resolved '
            + 'however.'
        ),
    },
    'hosts_deny': {
        'type': 'string',
        'name': 'hosts_deny',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of targets that are not authorized to '
            + 'be scanned. Supports the same syntax as the list targets. '
            + 'Both target hostnames and the address to which they resolve '
            + 'are checked. Hostnames in hosts_deny list are not '
            + 'resolved however.'
        ),
    },
}

VT_BASE_OID = "1.3.6.1.4.1.25623."


def safe_int(value: str) -> Optional[int]:
    """Convert a string into an integer and return None in case of errors
    during conversion
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


class OpenVasVtsFilter(VtsFilter):

    """Methods to overwrite the ones in the original class."""

    def __init__(self, nvticache: NVTICache) -> None:
        super().__init__()

        self.nvti = nvticache

    def format_vt_modification_time(self, value: str) -> str:
        """Convert the string seconds since epoch into a 19 character
        string representing YearMonthDayHourMinuteSecond,
        e.g. 20190319122532. This always refers to UTC.
        """

        return datetime.utcfromtimestamp(int(value)).strftime("%Y%m%d%H%M%S")

    def get_filtered_vts_list(self, vts, vt_filter: str) -> Optional[List[str]]:
        """Gets a collection of vulnerability test from the redis cache,
        which match the filter.

        Arguments:
            vt_filter: Filter to apply to the vts collection.
            vts: The complete vts collection.

        Returns:
            List with filtered vulnerability tests. The list can be empty.
            None in case of filter parse failure.
        """
        filters = self.parse_filters(vt_filter)
        if not filters:
            return None

        if not self.nvti:
            return None

        vt_oid_list = [vtlist[1] for vtlist in self.nvti.get_oids()]
        vt_oid_list_temp = copy.copy(vt_oid_list)
        vthelper = VtHelper(self.nvti)

        for element, oper, filter_val in filters:
            for vt_oid in vt_oid_list_temp:
                if vt_oid not in vt_oid_list:
                    continue

                vt = vthelper.get_single_vt(vt_oid)
                if vt is None or not vt.get(element):
                    vt_oid_list.remove(vt_oid)
                    continue

                elem_val = vt.get(element)
                val = self.format_filter_value(element, elem_val)

                if self.filter_operator[oper](val, filter_val):
                    continue
                else:
                    vt_oid_list.remove(vt_oid)

        return vt_oid_list


class OSPDopenvas(OSPDaemon):

    """ Class for ospd-openvas daemon. """

    def __init__(
        self, *, niceness=None, lock_file_dir='/var/lib/openvas', **kwargs
    ):
        """ Initializes the ospd-openvas daemon's internal data. """
        self.main_db = MainDB()
        self.nvti = NVTICache(self.main_db)

        super().__init__(
            customvtfilter=OpenVasVtsFilter(self.nvti),
            storage=dict,
            file_storage_dir=lock_file_dir,
            **kwargs,
        )

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

    def init(self, server: BaseServer) -> None:

        self.scan_collection.init()

        server.start(self.handle_client_stream)

        self.scanner_info['version'] = Openvas.get_version()

        self.set_params_from_openvas_settings()

        with self.feed_lock.wait_for_lock():
            Openvas.load_vts_into_redis()
            current_feed = self.nvti.get_feed_version()
            self.set_vts_version(vts_version=current_feed)

            logger.debug("Calculating vts integrity check hash...")
            vthelper = VtHelper(self.nvti)
            self.vts.sha256_hash = vthelper.calculate_vts_collection_hash()

        self.initialized = True

    def set_params_from_openvas_settings(self):
        """Set OSPD_PARAMS with the params taken from the openvas executable."""
        param_list = Openvas.get_settings()

        for elem in param_list:
            if elem not in OSPD_PARAMS:
                self.scan_only_params[elem] = param_list[elem]
            else:
                OSPD_PARAMS[elem]['default'] = param_list[elem]

    def feed_is_outdated(self, current_feed: str) -> Optional[bool]:
        """Compare the current feed with the one in the disk.

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
        if current_feed is None:
            logger.debug(
                "Wrong PLUGIN_SET format in plugins feed file %s. Format has to"
                " be yyyymmddhhmm. For example 'PLUGIN_SET = \"201910251033\"'",
                feed_info_file,
            )

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

    def check_feed(self):
        """Check if there is a feed update.

        Wait until all the running scans finished. Set a flag to announce there
        is a pending feed update, which avoids to start a new scan.
        """
        if not self.vts.is_cache_available:
            return

        current_feed = self.nvti.get_feed_version()
        is_outdated = self.feed_is_outdated(current_feed)

        # Check if the nvticache in redis is outdated
        if not current_feed or is_outdated:
            with self.feed_lock as fl:
                if fl.has_lock():
                    self.initialized = False
                    Openvas.load_vts_into_redis()
                    current_feed = self.nvti.get_feed_version()
                    self.set_vts_version(vts_version=current_feed)

                    vthelper = VtHelper(self.nvti)
                    self.vts.sha256_hash = (
                        vthelper.calculate_vts_collection_hash()
                    )
                    self.initialized = True
                else:
                    logger.debug(
                        "The feed was not upload or it is outdated, "
                        "but other process is locking the update. "
                        "Trying again later..."
                    )
                    return

    def scheduler(self):
        """This method is called periodically to run tasks."""
        self.check_feed()

    def get_vt_iterator(
        self, vt_selection: List[str] = None, details: bool = True
    ) -> Iterator[Tuple[str, Dict]]:
        vthelper = VtHelper(self.nvti)
        return vthelper.get_vt_iterator(vt_selection, details)

    @staticmethod
    def get_custom_vt_as_xml_str(vt_id: str, custom: Dict) -> str:
        """Return an xml element with custom metadata formatted as string.
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
        """Return an xml element with severities as string.
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
        """Return an xml element with params formatted as string.
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
        """Return an xml element with references formatted as string.
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
                        except ValueError as e:
                            logger.error(
                                'Not possible to parse xref "%s" for VT %s: %s',
                                xref,
                                vt_id,
                                e,
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
        """Return  an xml element with dependencies as string.
        Arguments:
            vt_id: VT OID. Only used for logging in error case.
            vt_dependencies: List with the VT dependencies.
        Return:
            Xml element as string.
        """
        vt_deps_xml = Element('dependencies')
        for dep in vt_dependencies:
            _vt_dep = Element('dependency')
            if VT_BASE_OID in dep:
                _vt_dep.set('vt_id', dep)
            else:
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
        """Return creation time as string.
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
        """Return modification time as string.
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
        """Return summary as string.
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
        """Return impact as string.

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
        """Return affected as string.
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
        """Return insight as string.
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
        """Return solution as string.
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
        """Return detection as string.
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
        """Checks that openvas command line tool is found and
        is executable."""
        has_openvas = Openvas.check()
        if not has_openvas:
            logger.error(
                'openvas executable not available. Please install openvas'
                ' into your PATH.'
            )
        return has_openvas

    def update_progress(self, scan_id: str, current_host: str, msg: str):
        """Calculate percentage and update the scan status of a host
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

        try:
            if float(total) == 0:
                return
            elif float(total) == ScanProgress.DEAD_HOST:
                host_prog = ScanProgress.DEAD_HOST
            else:
                host_prog = int((float(launched) / float(total)) * 100)
        except TypeError:
            return

        self.set_scan_host_progress(
            scan_id, host=current_host, progress=host_prog
        )
        logger.debug(
            '%s: Host %s has progress: %d', scan_id, current_host, host_prog
        )

    def report_openvas_scan_status(
        self, scan_db: ScanDB, scan_id: str, current_host: str
    ):
        """Get all status entries from redis kb.

        Arguments:
            scan_id: Scan ID to identify the current scan.
            current_host: Host to be updated.
        """
        res = scan_db.get_scan_status()
        while res:
            self.update_progress(scan_id, current_host, res)
            res = scan_db.get_scan_status()

    def get_severity_score(self, vt_aux: dict) -> Optional[float]:
        """Return the severity score for the given oid.
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
    ) -> int:
        """ Get all result entries from redis kb. """

        vthelper = VtHelper(self.nvti)

        # Result messages come in the next form, with optional uri field
        # type ||| hostname ||| port ||| OID ||| value [|||uri]
        all_results = db.get_result()
        res_list = ResultList()
        total_dead = 0
        total_results = len(all_results)

        for res in all_results:
            if not res:
                continue

            msg = res.split('|||')
            roid = msg[3].strip()
            rqod = ''
            rname = ''
            rhostname = msg[1].strip() if msg[1] else ''
            host_is_dead = "Host dead" in msg[4] or msg[0] == "DEADHOST"
            host_count = msg[0] == "HOSTS_COUNT"
            host_deny = "Host access denied" in msg[4]
            vt_aux = None

            # URI is optional and msg list length must be checked
            ruri = ''
            if len(msg) > 5:
                ruri = msg[5]

            if roid and not host_is_dead and not host_deny and not host_count:
                vt_aux = vthelper.get_single_vt(roid)

            if (
                not vt_aux
                and not host_is_dead
                and not host_deny
                and not host_count
            ):
                logger.warning('Invalid VT oid %s for a result', roid)

            if vt_aux:
                if vt_aux.get('qod_type'):
                    qod_t = vt_aux.get('qod_type')
                    rqod = self.nvti.QOD_TYPES[qod_t]
                elif vt_aux.get('qod'):
                    rqod = vt_aux.get('qod')

                rname = vt_aux.get('name')

            if msg[0] == 'ERRMSG':
                # Some errors are generated before a host is scanned
                # use the hostname passed in the message if
                # no current host is available.
                if not current_host and rhostname:
                    current_host = rhostname

                res_list.add_scan_error_to_list(
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                    port=msg[2],
                    test_id=roid,
                    uri=ruri,
                )

            if msg[0] == 'LOG':
                res_list.add_scan_log_to_list(
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                    port=msg[2],
                    qod=rqod,
                    test_id=roid,
                    uri=ruri,
                )

            if msg[0] == 'HOST_DETAIL':
                res_list.add_scan_host_detail_to_list(
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                    uri=ruri,
                )

            if msg[0] == 'ALARM':
                rseverity = self.get_severity_score(vt_aux)
                res_list.add_scan_alarm_to_list(
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                    port=msg[2],
                    test_id=roid,
                    severity=rseverity,
                    qod=rqod,
                    uri=ruri,
                )

            # To process non-scanned dead hosts when
            # test_alive_host_only in openvas is enable
            if msg[0] == 'DEADHOST':
                try:
                    total_dead = int(msg[4])
                except TypeError:
                    logger.debug('Error processing dead host count')

            # To update total host count
            if msg[0] == 'HOSTS_COUNT':
                try:
                    count_total = int(msg[4])
                    logger.debug(
                        '%s: Set total hosts counted by OpenVAS: %d',
                        scan_id,
                        count_total,
                    )
                    self.set_scan_total_hosts(scan_id, count_total)
                except TypeError:
                    logger.debug('Error processing total host count')

        # Insert result batch into the scan collection table.
        if len(res_list):
            self.scan_collection.add_result_list(scan_id, res_list)
            logger.debug(
                '%s: Inserting %d results into scan collection table',
                scan_id,
                len(res_list),
            )
        if total_dead:
            self.scan_collection.set_amount_dead_hosts(
                scan_id, total_dead=total_dead
            )
            logger.debug(
                '%s: Set %d hosts as dead counted by OpenVAS',
                scan_id,
                total_dead,
            )
        return total_results

    def report_openvas_timestamp_scan_host(
        self, scan_db: ScanDB, scan_id: str, host: str
    ):
        """ Get start and end timestamp of a host scan from redis kb. """
        timestamp = scan_db.get_host_scan_end_time()
        if timestamp:
            self.add_scan_log(
                scan_id, host=host, name='HOST_END', value=timestamp
            )
            logger.debug('%s: Host %s set HOST_END', scan_id, host)
            return

        timestamp = scan_db.get_host_scan_start_time()
        if timestamp:
            self.add_scan_log(
                scan_id, host=host, name='HOST_START', value=timestamp
            )
            logger.debug('%s: Host %s set HOST_START', scan_id, host)
            return

    def is_openvas_process_alive(
        self, kbdb: BaseDB, ovas_pid: str, openvas_scan_id: str
    ) -> bool:
        parent_exists = True
        parent = None
        try:
            parent = psutil.Process(int(ovas_pid))
        except psutil.NoSuchProcess:
            logger.debug('Process with pid %s already stopped', ovas_pid)
            parent_exists = False
        except TypeError:
            logger.debug(
                'Scan with ID %s never started or stopped unexpectedly',
                openvas_scan_id,
            )
            parent_exists = False

        is_zombie = False
        if parent and parent.status() == psutil.STATUS_ZOMBIE:
            logger.debug(
                ' %s: OpenVAS process is a zombie process',
                openvas_scan_id,
            )
            is_zombie = True

        if (not parent_exists or is_zombie) and kbdb:
            if kbdb and kbdb.scan_is_stopped(openvas_scan_id):
                return True
            return False

        return True

    def stop_scan_cleanup(  # pylint: disable=arguments-differ
        self, global_scan_id: str
    ):
        """Set a key in redis to indicate the wrapper is stopped.
        It is done through redis because it is a new multiprocess
        instance and it is not possible to reach the variables
        of the grandchild process.
        Indirectly sends SIGUSR1 to the running openvas scan process
        via an invocation of openvas with the --scan-stop option to
        stop it."""

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
                        'Not possible to stop scan process: %s.',
                        parent,
                    )
                    return False

                logger.debug('Stopping process: %s', parent)

                while parent:
                    if parent.is_running():
                        time.sleep(0.1)
                    else:
                        parent = None

            for scan_db in kbdb.get_scan_databases():
                self.main_db.release_database(scan_db)

    def exec_scan(self, scan_id: str):
        """ Starts the OpenVAS scanner for scan_id scan. """
        do_not_launch = False
        kbdb = self.main_db.get_new_kb_database()
        scan_prefs = PreferenceHandler(
            scan_id, kbdb, self.scan_collection, self.nvti
        )
        openvas_scan_id = scan_prefs.prepare_openvas_scan_id_for_openvas()
        scan_prefs.prepare_target_for_openvas()

        if not scan_prefs.prepare_ports_for_openvas():
            self.add_scan_error(
                scan_id, name='', host='', value='No port list defined.'
            )
            do_not_launch = True

        # Set credentials
        if not scan_prefs.prepare_credentials_for_openvas():
            self.add_scan_error(
                scan_id, name='', host='', value='Malformed credential.'
            )
            do_not_launch = True

        if not scan_prefs.prepare_plugins_for_openvas():
            self.add_scan_error(
                scan_id, name='', host='', value='No VTS to run.'
            )
            do_not_launch = True

        scan_prefs.prepare_main_kbindex_for_openvas()
        scan_prefs.prepare_host_options_for_openvas()
        scan_prefs.prepare_scan_params_for_openvas(OSPD_PARAMS)
        scan_prefs.prepare_reverse_lookup_opt_for_openvas()
        scan_prefs.prepare_alive_test_option_for_openvas()

        # VT preferences are stored after all preferences have been processed,
        # since alive tests preferences have to be able to overwrite default
        # preferences of ping_host.nasl for the classic method.
        scan_prefs.prepare_nvt_preferences()
        scan_prefs.prepare_boreas_alive_test()

        # Release memory used for scan preferences.
        del scan_prefs

        if do_not_launch or kbdb.scan_is_stopped(openvas_scan_id):
            self.main_db.release_database(kbdb)
            return

        result = Openvas.start_scan(
            openvas_scan_id,
            not self.is_running_as_root and self.sudo_available,
            self._niceness,
        )

        if result is None:
            self.main_db.release_database(kbdb)
            return

        ovas_pid = result.pid
        kbdb.add_scan_process_id(ovas_pid)
        logger.debug('pid = %s', ovas_pid)

        # Wait until the scanner starts and loads all the preferences.
        while kbdb.get_status(openvas_scan_id) == 'new':
            res = result.poll()
            if res and res < 0:
                self.stop_scan_cleanup(scan_id)
                logger.error(
                    'It was not possible run the task %s, since openvas ended '
                    'unexpectedly with errors during launching.',
                    scan_id,
                )
                return

            time.sleep(1)

        no_id_found = False
        got_results = False
        while True:
            if not kbdb.target_is_finished(
                scan_id
            ) and not self.is_openvas_process_alive(
                kbdb, ovas_pid, openvas_scan_id
            ):
                logger.error(
                    'Task %s was unexpectedly stopped or killed.',
                    scan_id,
                )
                self.add_scan_error(
                    scan_id,
                    name='',
                    host='',
                    value='Task was unexpectedly stopped or killed.',
                )

                # check for scanner error messages before leaving.
                self.report_openvas_results(kbdb, scan_id, "")

                kbdb.stop_scan(openvas_scan_id)
                for scan_db in kbdb.get_scan_databases():
                    self.main_db.release_database(scan_db)
                self.main_db.release_database(kbdb)
                return

            # Wait a second before trying to get result from redis if there
            # was no results before.
            # Otherwise, wait 50 msec to give access other process to redis.
            if not got_results:
                time.sleep(1)
            else:
                time.sleep(0.05)
            got_results = False

            # Check if the client stopped the whole scan
            if kbdb.scan_is_stopped(openvas_scan_id):
                logger.debug('%s: Scan stopped by the client', scan_id)
                # clean main_db, but wait for scanner to finish.
                while not kbdb.target_is_finished(scan_id):
                    logger.debug('%s: Waiting the scan to finish', scan_id)
                    time.sleep(1)
                self.main_db.release_database(kbdb)
                return

            self.report_openvas_results(kbdb, scan_id, "")

            res_count = 0
            for scan_db in kbdb.get_scan_databases():
                id_aux = scan_db.get_scan_id()
                if not id_aux:
                    continue

                if id_aux == openvas_scan_id:
                    no_id_found = False
                    current_host = scan_db.get_host_ip()

                    res_count += self.report_openvas_results(
                        scan_db, scan_id, current_host
                    )
                    if res_count > 0:
                        got_results = True

                    self.report_openvas_scan_status(
                        scan_db, scan_id, current_host
                    )
                    self.report_openvas_timestamp_scan_host(
                        scan_db, scan_id, current_host
                    )

                    if scan_db.host_is_finished(openvas_scan_id):
                        # Check that the host status is updated. As it has
                        # finished, its stauts should be DEAD or FINISHED.
                        # Otherwise it is considered an error. It tries 3
                        # times until considered it an error
                        retry = 3
                        host_progress = self.get_scan_host_progress(
                            scan_id, current_host
                        )
                        while (
                            host_progress > -1 and host_progress < 100
                        ) and retry > 0:
                            logger.debug(
                                '%s: Host %s finished but its scan progress is '
                                'still %d. Retrying the host progress update '
                                'in 1 second',
                                scan_id,
                                current_host,
                                host_progress,
                            )
                            time.sleep(1)
                            self.report_openvas_scan_status(
                                scan_db, scan_id, current_host
                            )
                            retry -= 1
                            host_progress = self.get_scan_host_progress(
                                scan_id, current_host
                            )

                        if (
                            host_progress > -1 and host_progress < 100
                        ) and retry == 0:
                            self.add_scan_error(
                                scan_id,
                                name='',
                                host='',
                                value=(
                                    'The scan progress of host %s could not be '
                                    'properly updated.' % current_host
                                ),
                            )
                            logger.error(
                                '%s: Host %s finished but its scan progress '
                                'is %d.',
                                scan_id,
                                current_host,
                                host_progress,
                            )
                        # Set HOST_END timestamp
                        self.report_openvas_timestamp_scan_host(
                            scan_db, scan_id, current_host
                        )

                        if current_host:
                            self.sort_host_finished(
                                scan_id, finished_hosts=current_host
                            )

                        kbdb.remove_scan_database(scan_db)
                        self.main_db.release_database(scan_db)
                        logger.debug(
                            '%s: Release host KB of %s', scan_id, current_host
                        )

            # Scan end. No kb in use for this scan id
            if no_id_found and kbdb.target_is_finished(scan_id):
                logger.debug('%s: Target is finished', scan_id)
                break

            no_id_found = True

        # Delete keys from KB related to this scan task.
        logger.debug('%s: End Target. Release main database', scan_id)
        self.main_db.release_database(kbdb)


def main():
    """ OSP openvas main function. """
    daemon_main('OSPD - openvas', OSPDopenvas)


if __name__ == '__main__':
    main()
