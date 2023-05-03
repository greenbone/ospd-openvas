# -*- coding: utf-8 -*-
# Copyright (C) 2014-2021 Greenbone AG
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

from typing import Optional, Dict, List, Tuple, Iterator, Any
from datetime import datetime

from pathlib import Path
from os import geteuid, environ

import psutil

from ospd.ospd import OSPDaemon
from ospd.scan import ScanProgress, ScanStatus
from ospd.server import BaseServer
from ospd.main import main as daemon_main
from ospd.vtfilter import VtsFilter
from ospd.resultlist import ResultList

from ospd_openvas import __version__
from ospd_openvas.errors import OspdOpenvasError

from ospd_openvas.notus import Cache, Notus, NotusParser, NotusResultHandler
from ospd_openvas.dryrun import DryRun
from ospd_openvas.messages.result import ResultMessage
from ospd_openvas.nvticache import NVTICache
from ospd_openvas.db import MainDB, BaseDB
from ospd_openvas.lock import LockFile
from ospd_openvas.preferencehandler import PreferenceHandler
from ospd_openvas.openvas import NASLCli, Openvas
from ospd_openvas.vthelper import VtHelper
from ospd_openvas.messaging.mqtt import MQTTClient, MQTTDaemon, MQTTSubscriber

SENTRY_DSN_OSPD_OPENVAS = environ.get("SENTRY_DSN_OSPD_OPENVAS")
if SENTRY_DSN_OSPD_OPENVAS:
    # pylint: disable=import-error
    import sentry_sdk

    sentry_sdk.init(  # pylint: disable=abstract-class-instantiated
        SENTRY_DSN_OSPD_OPENVAS,
        traces_sample_rate=1.0,
        server_name=environ.get('SENTRY_SERVER_NAME'),
        environment=environ.get('SENTRY_ENVIRONMENT'),
    )

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
    'alive_test_ports': {
        'type': 'string',
        'name': 'alive_test_ports',
        'default': '21-23,25,53,80,110-111,135,139,143,443,445,'
        + '993,995,1723,3306,3389,5900,8080',
        'mandatory': 0,
        'visible_for_client': True,
        'description': ('Port list used for host alive detection.'),
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
    'test_alive_wait_timeout': {
        'type': 'integer',
        'name': 'test_alive_wait_timeout',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'This is the default timeout to wait for replies after last '
            + 'packet was sent.'
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
    'results_per_host': {
        'type': 'integer',
        'name': 'results_per_host',
        'default': 10,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Amount of fake results generated per each host in the target '
            + 'list for a dry run scan.'
        ),
    },
    'table_driven_lsc': {
        'type': 'boolean',
        'name': 'table_driven_lsc',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'If this option is enabled a scanner for table_driven_lsc will '
            + 'scan package results.'
        ),
    },
}


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

    def __init__(self, nvticache: NVTICache, notus: Notus) -> None:
        super().__init__()

        self.nvti = nvticache
        self.notus = notus

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

        # build a list with nvts and notus advisories
        nvt_oid_list = [vtlist[1] for vtlist in self.nvti.get_oids()]
        if self.notus:
            notus_oid_list = [vtlist[1] for vtlist in self.notus.get_oids()]
            vt_oid_list = notus_oid_list + nvt_oid_list
        else:
            vt_oid_list = nvt_oid_list

        vt_oid_list_temp = copy.copy(vt_oid_list)
        vthelper = VtHelper(self.nvti, self.notus)

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

    """Class for ospd-openvas daemon."""

    def __init__(
        self,
        *,
        niceness=None,
        lock_file_dir='/var/lib/openvas',
        mqtt_broker_address="localhost",
        mqtt_broker_port=1883,
        feed_updater="openvas",
        disable_notus_hashsum_verification=False,
        **kwargs,
    ):
        """Initializes the ospd-openvas daemon's internal data."""

        self.main_db = MainDB()
        notus_dir = kwargs.get('notus_feed_dir')
        self.notus = None
        if notus_dir:
            ndir = Path(notus_dir)
            self.notus = Notus(
                ndir,
                Cache(self.main_db),
                disable_notus_hashsum_verification,
            )

        self.feed_updater = feed_updater
        self.nvti = NVTICache(self.main_db)

        super().__init__(
            customvtfilter=OpenVasVtsFilter(self.nvti, self.notus),
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

        self._mqtt_broker_address = mqtt_broker_address
        self._mqtt_broker_port = mqtt_broker_port

    def init(self, server: BaseServer) -> None:
        notus_handler = NotusResultHandler(self.report_results)

        if self._mqtt_broker_address:
            client = MQTTClient(
                self._mqtt_broker_address, self._mqtt_broker_port, "ospd"
            )
            daemon = MQTTDaemon(client)
            subscriber = MQTTSubscriber(client)

            subscriber.subscribe(ResultMessage, notus_handler.result_handler)
            daemon.run()
        else:
            logger.info(
                "MQTT Broker Adress empty. MQTT disabled. Unable to get Notus"
                " results."
            )

        self.scan_collection.init()

        server.start(self.handle_client_stream)

        self.scanner_info['version'] = Openvas.get_version()

        self.set_params_from_openvas_settings()

        with self.feed_lock.wait_for_lock():
            self.update_vts()
            self.set_feed_info()

            logger.debug("Calculating vts integrity check hash...")
            vthelper = VtHelper(self.nvti, self.notus)
            self.vts.sha256_hash = vthelper.calculate_vts_collection_hash()

        self.initialized = True

    def set_params_from_openvas_settings(self):
        """Set OSPD_PARAMS with the params taken from the openvas executable."""
        param_list = Openvas.get_settings()

        for elem in param_list:  # pylint: disable=consider-using-dict-items
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
        current_feed = safe_int(current_feed)
        if current_feed is None:
            logger.debug(
                "Wrong PLUGIN_SET format in plugins feed file "
                "'plugin_feed_info.inc'. Format has to"
                " be yyyymmddhhmm. For example 'PLUGIN_SET = \"201910251033\"'"
            )

        feed_date = None
        feed_info = self.get_feed_info()
        if feed_info:
            feed_date = safe_int(feed_info.get("PLUGIN_SET"))

        logger.debug("Current feed version: %s", current_feed)
        logger.debug("Plugin feed version: %s", feed_date)

        return (
            (not feed_date) or (not current_feed) or (current_feed < feed_date)
        )

    def get_feed_info(self) -> Dict[str, Any]:
        """Parses the current plugin_feed_info.inc file"""

        plugins_folder = self.scan_only_params.get('plugins_folder')
        if not plugins_folder:
            raise OspdOpenvasError("Error: Path to plugins folder not found.")

        feed_info_file = Path(plugins_folder) / 'plugin_feed_info.inc'
        if not feed_info_file.exists():
            self.set_params_from_openvas_settings()
            logger.debug('Plugins feed file %s not found.', feed_info_file)
            return {}

        feed_info = {}
        with feed_info_file.open(encoding='utf-8') as fcontent:
            for line in fcontent:
                try:
                    key, value = line.split('=', 1)
                except ValueError:
                    continue
                key = key.strip()
                value = value.strip()
                value = value.replace(';', '')
                value = value.replace('"', '')
                if value:
                    feed_info[key] = value

        return feed_info

    def set_feed_info(self):
        """Set feed current information to be included in the response of
        <get_version/> command
        """
        current_feed = self.nvti.get_feed_version()
        self.set_vts_version(vts_version=current_feed)

        feed_info = self.get_feed_info()
        self.set_feed_vendor(feed_info.get("FEED_VENDOR", "unknown"))
        self.set_feed_home(feed_info.get("FEED_HOME", "unknown"))
        self.set_feed_name(feed_info.get("PLUGIN_FEED", "unknown"))

    def check_feed_self_test(self) -> Dict:
        """Perform a feed sync self tests and check if the feed lock file is
        locked.
        """
        feed_status = dict()

        # It is locked by the current process
        if self.feed_lock.has_lock():
            feed_status["lockfile_in_use"] = '1'
        # Check if we can get the lock
        else:
            with self.feed_lock as fl:
                # It is available
                if fl.has_lock():
                    feed_status["lockfile_in_use"] = '0'
                # Locked by another process
                else:
                    feed_status["lockfile_in_use"] = '1'

        # The feed self test is not performed any more, but the following
        # entries are kept for backward compatibility.
        feed_status["self_test_exit_error"] = "0"
        feed_status["self_test_error_msg"] = None

        return feed_status

    def update_vts(self):
        """Updates VTs in redis via the openvas-scanner"""
        logger.info(
            "Loading VTs. Scans will be [requested|queued] until VTs are"
            " loaded. This may take a few minutes, please wait..."
        )
        old = self.nvti.get_feed_version() or 0
        # reload notus cache
        if self.notus:
            self.notus.reload_cache()
        loaded = False
        if self.feed_updater == "nasl-cli":
            loaded = NASLCli.load_vts_into_redis()
        else:
            loaded = Openvas.load_vts_into_redis()

        if loaded:
            new = self.nvti.get_feed_version()
            if new != old:
                logger.info(
                    "Finished loading VTs. The VT cache has been updated from"
                    " version %s to %s.",
                    old,
                    new,
                )
            else:
                logger.info("VTs were up to date. Feed version is %s.", new)
        else:
            logger.error("Updating VTs failed.")

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
                    self.update_vts()
                    self.set_feed_info()

                    vthelper = VtHelper(self.nvti, self.notus)
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
        vthelper = VtHelper(self.nvti, self.notus)
        return vthelper.get_vt_iterator(vt_selection, details)

    @property
    def is_running_as_root(self) -> bool:
        """Check if it is running as root user."""
        if self._is_running_as_root is not None:
            return self._is_running_as_root

        self._is_running_as_root = False
        if geteuid() == 0:
            self._is_running_as_root = True

        return self._is_running_as_root

    @property
    def sudo_available(self) -> bool:
        """Checks that sudo is available"""
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

    def report_openvas_scan_status(self, kbdb: BaseDB, scan_id: str):
        """Get all status entries from redis kb.

        Arguments:
            kbdb: KB context where to get the status from.
            scan_id: Scan ID to identify the current scan.
        """
        all_status = kbdb.get_scan_status()
        all_hosts = dict()
        finished_hosts = list()
        for res in all_status:
            try:
                current_host, launched, total = res.split('/')
            except ValueError:
                continue

            try:
                if float(total) == 0:
                    continue
                elif float(total) == ScanProgress.DEAD_HOST:
                    host_prog = ScanProgress.DEAD_HOST
                else:
                    host_prog = int((float(launched) / float(total)) * 100)
            except TypeError:
                continue

            all_hosts[current_host] = host_prog

            if (
                host_prog == ScanProgress.DEAD_HOST
                or host_prog == ScanProgress.FINISHED
            ):
                finished_hosts.append(current_host)

            logger.debug(
                '%s: Host %s has progress: %d', scan_id, current_host, host_prog
            )

        self.set_scan_progress_batch(scan_id, host_progress=all_hosts)

        self.sort_host_finished(scan_id, finished_hosts)

    def report_openvas_results(self, db: BaseDB, scan_id: str) -> bool:
        """Get all result entries from redis kb.

        Arguments:
            db: KB context where to get the results from.
            scan_id: Scan ID to identify the current scan.
        """

        # result_type|||host ip|||hostname|||port|||OID|||value[|||uri]
        all_results = db.get_result()
        results = []
        for res in all_results:
            if not res:
                continue
            msg = res.split('|||')
            result = {
                "result_type": msg[0],
                "host_ip": msg[1],
                "host_name": msg[2],
                "port": msg[3],
                "oid": msg[4],
                "value": msg[5],
            }
            if len(msg) > 6:
                result["uri"] = msg[6]

            results.append(result)

        return self.report_results(results, scan_id)

    def report_results(self, results: list, scan_id: str) -> bool:
        """Reports all results given in a list.

        Arguments:
            results: list of results each list item must contain a dictionary
            with following fields: result_type, host_ip, host_name, port, oid,
            value, uri (optional)

        Returns:
            True if the results have been reported
        """
        if not self.scan_collection.id_exists(scan_id):
            logger.warning("Unknown scan_id %s", scan_id)
            return False

        vthelper = VtHelper(self.nvti, self.notus)

        res_list = ResultList()
        total_dead = 0
        for res in results:
            if not res:
                continue

            roid = res["oid"].strip()
            rqod = ''
            rname = ''
            current_host = res["host_ip"].strip() if res["host_ip"] else ''
            rhostname = res["host_name"].strip() if res["host_name"] else ''
            host_is_dead = (
                "Host dead" in res["value"] or res["result_type"] == "DEADHOST"
            )
            host_deny = "Host access denied" in res["value"]
            start_end_msg = (
                res["result_type"] == "HOST_START"
                or res["result_type"] == "HOST_END"
            )
            host_count = res["result_type"] == "HOSTS_COUNT"
            vt_aux = None

            # URI is optional and containing must be checked
            ruri = res["uri"] if "uri" in res else ""

            if (
                not host_is_dead
                and not host_deny
                and not start_end_msg
                and not host_count
            ):
                if not roid and res["result_type"] != 'ERRMSG':
                    logger.warning('Missing VT oid for a result')
                vt_aux = vthelper.get_single_vt(roid)
                if not vt_aux:
                    logger.warning('Invalid VT oid %s for a result', roid)
                else:
                    if vt_aux.get('qod_type'):
                        qod_t = vt_aux.get('qod_type')
                        rqod = self.nvti.QOD_TYPES[qod_t]
                    elif vt_aux.get('qod'):
                        rqod = vt_aux.get('qod')

                    rname = vt_aux.get('name')

            if res["result_type"] == 'ERRMSG':
                res_list.add_scan_error_to_list(
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=res["value"],
                    port=res["port"],
                    test_id=roid,
                    uri=ruri,
                )

            elif (
                res["result_type"] == 'HOST_START'
                or res["result_type"] == 'HOST_END'
            ):
                res_list.add_scan_log_to_list(
                    host=current_host,
                    name=res["result_type"],
                    value=res["value"],
                )

            elif res["result_type"] == 'LOG':
                res_list.add_scan_log_to_list(
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=res["value"],
                    port=res["port"],
                    qod=rqod,
                    test_id=roid,
                    uri=ruri,
                )

            elif res["result_type"] == 'HOST_DETAIL':
                res_list.add_scan_host_detail_to_list(
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=res["value"],
                    uri=ruri,
                )

            elif res["result_type"] == 'ALARM':
                rseverity = vthelper.get_severity_score(vt_aux)
                res_list.add_scan_alarm_to_list(
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=res["value"],
                    port=res["port"],
                    test_id=roid,
                    severity=rseverity,
                    qod=rqod,
                    uri=ruri,
                )

            # To process non-scanned dead hosts when
            # test_alive_host_only in openvas is enable
            elif res["result_type"] == 'DEADHOST':
                try:
                    total_dead = total_dead + int(res["value"])
                except TypeError:
                    logger.debug('Error processing dead host count')

            # To update total host count
            if res["result_type"] == 'HOSTS_COUNT':
                try:
                    count_total = int(res["value"])
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
            logger.debug(
                '%s: Set dead hosts counted by OpenVAS: %d',
                scan_id,
                total_dead,
            )
            self.scan_collection.set_amount_dead_hosts(
                scan_id, total_dead=total_dead
            )

        return len(res_list) > 0

    @staticmethod
    def is_openvas_process_alive(openvas_process: psutil.Popen) -> bool:
        try:
            if openvas_process.status() == psutil.STATUS_ZOMBIE:
                logger.debug("Process is a Zombie, waiting for it to clean up")
                openvas_process.wait()
        except psutil.NoSuchProcess:
            return False

        return openvas_process.is_running()

    def stop_scan_cleanup(
        self,
        kbdb: BaseDB,
        scan_id: str,
        ovas_pid: str,  # pylint: disable=arguments-differ
    ):
        """Set a key in redis to indicate the wrapper is stopped.
        It is done through redis because it is a new multiprocess
        instance and it is not possible to reach the variables
        of the grandchild process.
        Indirectly sends SIGUSR1 to the running openvas scan process
        via an invocation of openvas with the --scan-stop option to
        stop it."""

        if kbdb:
            # Set stop flag in redis
            kbdb.stop_scan(scan_id)

            try:
                ovas_process = psutil.Process(int(ovas_pid))
            except psutil.NoSuchProcess:
                ovas_process = None

            # Check if openvas is running
            if (
                ovas_process
                and ovas_process.is_running()
                and ovas_process.name() == "openvas"
            ):
                # Cleaning in case of Zombie Process
                if ovas_process.status() == psutil.STATUS_ZOMBIE:
                    logger.debug(
                        '%s: Process with PID %s is a Zombie process.'
                        ' Cleaning up...',
                        scan_id,
                        ovas_process.pid,
                    )
                    ovas_process.wait()
                # Stop openvas process and wait until it stopped
                else:
                    can_stop_scan = Openvas.stop_scan(
                        scan_id,
                        not self.is_running_as_root and self.sudo_available,
                    )
                    if not can_stop_scan:
                        logger.debug(
                            'Not possible to stop scan process: %s.',
                            ovas_process,
                        )
                        return

                    logger.debug('Stopping process: %s', ovas_process)

                    while ovas_process.is_running():
                        if ovas_process.status() == psutil.STATUS_ZOMBIE:
                            ovas_process.wait()
                        else:
                            time.sleep(0.1)
            else:
                logger.debug(
                    "%s: Process with PID %s already stopped",
                    scan_id,
                    ovas_pid,
                )

            # Clean redis db
            for scan_db in kbdb.get_scan_databases():
                self.main_db.release_database(scan_db)

    def exec_scan(self, scan_id: str):
        """Starts the OpenVAS scanner for scan_id scan."""
        params = self.scan_collection.get_options(scan_id)
        if params.get("dry_run"):
            dryrun = DryRun(self)
            dryrun.exec_dry_run_scan(scan_id, self.nvti, OSPD_PARAMS)
            return

        kbdb, err = self.main_db.check_consistency(scan_id)
        if err < 0:
            logger.debug(
                "An old scan with the same scanID was found in the kb. "
                "Waiting for the kb clean up to finish."
            )
            self.stop_scan_cleanup(kbdb, scan_id, kbdb.get_scan_process_id())
            self.main_db.release_database(kbdb)

        do_not_launch = False
        kbdb = self.main_db.get_new_kb_database()
        scan_prefs = PreferenceHandler(
            scan_id, kbdb, self.scan_collection, self.nvti, self.notus.exists
        )
        kbdb.add_scan_id(scan_id)
        scan_prefs.prepare_target_for_openvas()

        if not scan_prefs.prepare_ports_for_openvas():
            self.add_scan_error(
                scan_id, name='', host='', value='Invalid port list.'
            )
            do_not_launch = True

        # Set credentials
        if not scan_prefs.prepare_credentials_for_openvas():
            error = (
                'All authentifications contain errors.'
                + 'Starting unauthenticated scan instead.'
            )
            self.add_scan_error(
                scan_id,
                name='',
                host='',
                value=error,
            )
            logger.error(error)
        errors = scan_prefs.get_error_messages()
        for e in errors:
            error = 'Malformed credential. ' + e
            self.add_scan_error(
                scan_id,
                name='',
                host='',
                value=error,
            )
            logger.error(error)

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

        scan_stopped = self.get_scan_status(scan_id) == ScanStatus.STOPPED
        if do_not_launch or kbdb.scan_is_stopped(scan_id) or scan_stopped:
            self.main_db.release_database(kbdb)
            return

        openvas_process = Openvas.start_scan(
            scan_id,
            not self.is_running_as_root and self.sudo_available,
            self._niceness,
        )

        if openvas_process is None:
            self.main_db.release_database(kbdb)
            return

        kbdb.add_scan_process_id(openvas_process.pid)
        logger.debug('pid = %s', openvas_process.pid)

        # Wait until the scanner starts and loads all the preferences.
        while kbdb.get_status(scan_id) == 'new':
            res = openvas_process.poll()
            if res and res < 0:
                self.stop_scan_cleanup(
                    kbdb, scan_id, kbdb.get_scan_process_id()
                )
                logger.error(
                    'It was not possible run the task %s, since openvas ended '
                    'unexpectedly with errors during launching.',
                    scan_id,
                )
                return

            time.sleep(1)

        got_results = False
        while True:
            openvas_process_is_alive = self.is_openvas_process_alive(
                openvas_process
            )
            target_is_finished = kbdb.target_is_finished(scan_id)
            scan_stopped = self.get_scan_status(scan_id) == ScanStatus.STOPPED

            # Report new Results and update status
            got_results = self.report_openvas_results(kbdb, scan_id)
            self.report_openvas_scan_status(kbdb, scan_id)

            # Check if the client stopped the whole scan
            if scan_stopped:
                logger.debug('%s: Scan stopped by the client', scan_id)

                self.stop_scan_cleanup(
                    kbdb, scan_id, kbdb.get_scan_process_id()
                )

                # clean main_db, but wait for scanner to finish.
                while not kbdb.target_is_finished(scan_id):
                    if not self.is_openvas_process_alive(openvas_process):
                        break
                    logger.debug('%s: Waiting for openvas to finish', scan_id)
                    time.sleep(1)
                self.main_db.release_database(kbdb)
                return

            # Scan end. No kb in use for this scan id
            if target_is_finished:
                logger.debug('%s: Target is finished', scan_id)
                break

            if not openvas_process_is_alive:
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
                self.report_openvas_results(kbdb, scan_id)

                kbdb.stop_scan(scan_id)

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

        # Sleep a second to be sure to get all notus results
        time.sleep(1)
        # Delete keys from KB related to this scan task.
        logger.debug('%s: End Target. Release main database', scan_id)
        self.main_db.release_database(kbdb)


def main():
    """OSP openvas main function."""

    daemon_main('OSPD - openvas', OSPDopenvas, NotusParser())


if __name__ == '__main__':
    main()
