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
import subprocess
import time
import uuid

from datetime import datetime

from pathlib import Path
from os import geteuid
from lxml.etree import tostring, SubElement, Element

import psutil

from ospd.errors import OspdError
from ospd.ospd import OSPDaemon
from ospd.main import main as daemon_main
from ospd.cvss import CVSS
from ospd.vtfilter import VtsFilter

from ospd_openvas import __version__
from ospd_openvas.errors import OspdOpenvasError

from ospd_openvas.nvticache import NVTICache
from ospd_openvas.db import OpenvasDB

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
    'use_mac_addr': {
        'type': 'boolean',
        'name': 'use_mac_addr',
        'default': 0,
        'mandatory': 0,
        'description': 'To test the local network. '
        + 'Hosts will be referred to by their MAC address.',
    },
    'vhosts': {
        'type': 'string',
        'name': 'vhosts',
        'default': '',
        'mandatory': 0,
        'description': '',
    },
    'vhosts_ip': {
        'type': 'string',
        'name': 'vhosts_ip',
        'default': '',
        'mandatory': 0,
        'description': '',
    },
}

OID_SSH_AUTH = "1.3.6.1.4.1.25623.1.0.103591"
OID_SMB_AUTH = "1.3.6.1.4.1.25623.1.0.90023"
OID_ESXI_AUTH = "1.3.6.1.4.1.25623.1.0.105058"
OID_SNMP_AUTH = "1.3.6.1.4.1.25623.1.0.105076"


def _from_bool_to_str(value):
    """ The OpenVAS scanner use yes and no as boolean values, whereas ospd
    uses 1 and 0."""
    return 'yes' if value == 1 else 'no'


class OpenVasVtsFilter(VtsFilter):
    """ Methods to overwrite the ones in the original class.
    Each method formats the value to be compatible with the filter
    """

    def format_vt_modification_time(self, value):
        """ Convert the string seconds since epoch into a 19 character
        string representing YearMonthDayHourMinuteSecond,
        e.g. 20190319122532. This always refers to UTC.
        """

        return datetime.utcfromtimestamp(int(value)).strftime("%Y%m%d%H%M%S")


class OSPDopenvas(OSPDaemon):

    """ Class for ospd-openvas daemon. """

    def __init__(self, *, niceness=None, **kwargs):
        """ Initializes the ospd-openvas daemon's internal data. """

        super().__init__(customvtfilter=OpenVasVtsFilter())

        self.server_version = __version__

        self._niceness = str(niceness)

        self.scanner_info['name'] = 'openvas'
        self.scanner_info['version'] = ''  # achieved during self.check()
        self.scanner_info['description'] = OSPD_DESC

        for name, param in OSPD_PARAMS.items():
            self.add_scanner_param(name, param)

        self._sudo_available = None
        self._is_running_as_root = None

        self.scan_only_params = dict()

        self.main_kbindex = None

        self.openvas_db = OpenvasDB()

        self.nvti = NVTICache(self.openvas_db)

        self.pending_feed = None

    def init(self):
        self.openvas_db.db_init()

        ctx = self.openvas_db.db_find(self.nvti.NVTICACHE_STR)

        if not ctx:
            self.redis_nvticache_init()
            ctx = self.openvas_db.db_find(self.nvti.NVTICACHE_STR)

        self.openvas_db.set_redisctx(ctx)

        self.load_vts()

    def parse_param(self):
        """ Set OSPD_PARAMS with the params taken from the openvas_scanner. """
        bool_dict = {'no': 0, 'yes': 1}

        result = subprocess.check_output(
            ['openvas', '-s'], stderr=subprocess.STDOUT
        )
        result = result.decode('ascii')
        param_list = dict()
        for conf in result.split('\n'):
            elem = conf.split('=')
            if len(elem) == 2:
                value = str.strip(elem[1])
                if str.strip(elem[1]) in bool_dict:
                    value = bool_dict[value]
                param_list[str.strip(elem[0])] = value
        for elem in OSPD_PARAMS:
            if elem in param_list:
                OSPD_PARAMS[elem]['default'] = param_list[elem]
        for elem in param_list:
            if elem not in OSPD_PARAMS:
                self.scan_only_params[elem] = param_list[elem]

    def redis_nvticache_init(self):
        """ Loads NVT's metadata into Redis DB. """
        try:
            logger.debug('Loading NVTs in Redis DB')
            subprocess.check_call(['openvas', '--update-vt-info'])
        except subprocess.CalledProcessError as err:
            logger.error('OpenVAS Scanner failed to load NVTs. %s', err)

    def feed_is_outdated(self, current_feed):
        """ Compare the current feed with the one in the disk.

        Return:
            False if there is no new feed.
            True if the feed version in disk is newer than the feed in
            redis cache.
            None if there is no feed
            the disk.
        """
        plugins_folder = self.scan_only_params.get('plugins_folder')
        if not plugins_folder:
            raise OspdOpenvasError("Error: Path to plugins folder not found.")

        feed_info_file = Path(plugins_folder) / 'plugin_feed_info.inc'
        if not feed_info_file.exists():
            self.parse_param()
            msg = 'Plugins feed file %s not found.' % feed_info_file
            logger.debug(msg)
            return None

        date = 0
        with open(str(feed_info_file)) as fcontent:
            for line in fcontent:
                if "PLUGIN_SET" in line:
                    date = line.split(' = ')[1]
                    date = date.replace(';', '')
                    date = date.replace('"', '')
        if int(current_feed) < int(date) or int(date) == 0:
            return True
        return False

    def check_feed(self):
        """ Check if there is a feed update. Wait until all the running
        scans finished. Set a flag to anounce there is a pending feed update,
        which avoid to start a new scan.
        """
        current_feed = self.nvti.get_feed_version()
        # Check if the feed is already accessible in the disk.
        if current_feed and self.feed_is_outdated(current_feed) is None:
            self.pending_feed = True
            return

        # Check if the nvticache in redis is outdated
        if not current_feed or self.feed_is_outdated(current_feed):
            self.redis_nvticache_init()
            ctx = self.openvas_db.db_find(self.nvti.NVTICACHE_STR)
            self.openvas_db.set_redisctx(ctx)
            self.pending_feed = True

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

        if _running_scan and _pending_feed:
            if not self.pending_feed:
                self.pending_feed = True
                logger.debug(
                    'There is a running scan. Therefore the feed '
                    'update will be performed later.'
                )
        elif not _running_scan and _pending_feed:
            self.vts = dict()
            self.load_vts()

    def scheduler(self):
        """This method is called periodically to run tasks."""
        self.check_feed()

    def load_vts(self):
        """ Load the NVT's metadata into the vts
        global  dictionary. """
        logger.debug('Loading vts in memory.')
        oids = dict(self.nvti.get_oids())
        for _filename, vt_id in oids.items():
            _vt_params = self.nvti.get_nvt_params(vt_id)
            _vt_refs = self.nvti.get_nvt_refs(vt_id)
            _custom = self.nvti.get_nvt_metadata(vt_id)
            _name = _custom.pop('name')
            _vt_creation_time = _custom.pop('creation_date')
            _vt_modification_time = _custom.pop('last_modification')

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

            _vt_dependencies = list()
            if 'dependencies' in _custom:
                _deps = _custom.pop('dependencies')
                _deps_list = _deps.split(', ')
                for dep in _deps_list:
                    _vt_dependencies.append(oids.get('filename:' + dep))

            try:
                self.add_vt(
                    vt_id,
                    name=_name,
                    vt_params=_vt_params,
                    vt_refs=_vt_refs,
                    custom=_custom,
                    vt_creation_time=_vt_creation_time,
                    vt_modification_time=_vt_modification_time,
                    vt_dependencies=_vt_dependencies,
                    summary=_summary,
                    impact=_impact,
                    affected=_affected,
                    insight=_insight,
                    solution=_solution,
                    solution_t=_solution_t,
                    detection=_vuldetect,
                    qod_t=_qod_t,
                    qod_v=_qod_v,
                    severities=_severity,
                )
            except OspdError as e:
                logger.info("Error while adding vt. %s", e)

        _feed_version = self.nvti.get_feed_version()
        self.set_vts_version(vts_version=_feed_version)
        self.pending_feed = False
        logger.debug('Finish loading up vts.')

    @staticmethod
    def get_custom_vt_as_xml_str(vt_id, custom):
        """ Return an xml element with custom metadata formatted as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            custom (dict): Dictionary with the custom metadata.
        Return:
            string: xml element as string.
        """

        _custom = Element('custom')
        for key, val in custom.items():
            xml_key = SubElement(_custom, key)
            xml_key.text = val

        return tostring(_custom).decode('utf-8')

    @staticmethod
    def get_severities_vt_as_xml_str(vt_id, severities):
        """ Return an xml element with severities as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            severities (dict): Dictionary with the severities.
        Return:
            string: xml element as string.
        """
        _severities = Element('severities')
        _severity = SubElement(_severities, 'severity')
        if 'severity_base_vector' in severities:
            _severity.text = severities.get('severity_base_vector')
        if 'severity_origin' in severities:
            _severity.set('origin', severities.get('severity_origin'))
        if 'severity_type' in severities:
            _severity.set('type', severities.get('severity_type'))

        return tostring(_severities).decode('utf-8')

    @staticmethod
    def get_params_vt_as_xml_str(vt_id, vt_params):
        """ Return an xml element with params formatted as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            vt_params (dict): Dictionary with the VT parameters.
        Return:
            string: xml element as string.
        """
        vt_params_xml = Element('params')
        for _pref_id, prefs in vt_params.items():
            vt_param = Element('param')
            vt_param.set('type', prefs['type'])
            vt_param.set('id', _pref_id)
            xml_name = SubElement(vt_param, 'name')
            xml_name.text = prefs['name']
            if prefs['default']:
                xml_def = SubElement(vt_param, 'default')
                xml_def.text = prefs['default']
            vt_params_xml.append(vt_param)

        return tostring(vt_params_xml).decode('utf-8')

    @staticmethod
    def get_refs_vt_as_xml_str(vt_id, vt_refs):
        """ Return an xml element with references formatted as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            vt_refs (dict): Dictionary with the VT references.
        Return:
            string: xml element as string.
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
                                'Not possible to parse xref %s for vt %s',
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
        vt_id, dep_list
    ):  # pylint: disable=arguments-differ
        """ Return  an xml element with dependencies as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            dep_list (List): List with the VT dependencies.
        Return:
            string: xml element as string.
        """
        vt_deps_xml = Element('dependencies')
        for dep in dep_list:
            _vt_dep = Element('dependency')
            try:
                _vt_dep.set('vt_id', dep)
            except TypeError:
                logger.error(
                    'Not possible to add dependency %s for vt %s', dep, vt_id
                )
                continue
            vt_deps_xml.append(_vt_dep)

        return tostring(vt_deps_xml).decode('utf-8')

    @staticmethod
    def get_creation_time_vt_as_xml_str(
        vt_id, creation_time
    ):  # pylint: disable=arguments-differ
        """ Return creation time as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            creation_time (str): String with the VT creation time.
        Return:
            string: xml element as string.
        """
        _time = Element('creation_time')
        _time.text = creation_time
        return tostring(_time).decode('utf-8')

    @staticmethod
    def get_modification_time_vt_as_xml_str(
        vt_id, modification_time
    ):  # pylint: disable=arguments-differ
        """ Return modification time as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            modification_time (str): String with the VT modification time.
        Return:
            string: xml element as string.
        """
        _time = Element('modification_time')
        _time.text = modification_time
        return tostring(_time).decode('utf-8')

    @staticmethod
    def get_summary_vt_as_xml_str(vt_id, summary):
        """ Return summary as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            summary (str): String with a VT summary.
        Return:
            string: xml element as string.
        """
        _summary = Element('summary')
        _summary.text = summary
        return tostring(_summary).decode('utf-8')

    @staticmethod
    def get_impact_vt_as_xml_str(vt_id, impact):
        """ Return impact as string.

        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            impact (str): String which explain the vulneravility impact.
        Return:
            string: xml element as string.
        """
        _impact = Element('impact')
        _impact.text = impact
        return tostring(_impact).decode('utf-8')

    @staticmethod
    def get_affected_vt_as_xml_str(vt_id, affected):
        """ Return affected as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            affected (str): String which explain what is affected.
        Return:
            string: xml element as string.
        """
        _affected = Element('affected')
        _affected.text = affected
        return tostring(_affected).decode('utf-8')

    @staticmethod
    def get_insight_vt_as_xml_str(vt_id, insight):
        """ Return insight as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            insight (str): String giving an insight of the vulnerability.
        Return:
            string: xml element as string.
        """
        _insight = Element('insight')
        _insight.text = insight
        return tostring(_insight).decode('utf-8')

    @staticmethod
    def get_solution_vt_as_xml_str(vt_id, solution, solution_type=None):
        """ Return solution as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            solution (str): String giving a possible solution.
            solution_type (str): A solution type
        Return:
            string: xml element as string.
        """
        _solution = Element('solution')
        _solution.text = solution
        if solution_type:
            _solution.set('type', solution_type)
        return tostring(_solution).decode('utf-8')

    @staticmethod
    def get_detection_vt_as_xml_str(
        vt_id, vuldetect=None, qod_type=None, qod=None
    ):  # pylint: disable=arguments-differ
        """ Return detection as string.
        Arguments:
            vt_id (str): VT OID. Only used for logging in error case.
            vuldetect (str, opt): String which explain how the vulnerability
                was detected.
            qod_type (str, opt): qod type.
            qod (str, opt): qod value.
        Return:
            string: xml element as string.
        """
        _detection = Element('detection')
        if vuldetect:
            _detection.text = vuldetect
        if qod_type:
            _detection.set('qod_type', qod_type)
        elif qod:
            _detection.set('qod', qod)

        return tostring(_detection).decode('utf-8')

    @property
    def is_running_as_root(self):
        """ Check if it is running as root user."""
        if self._is_running_as_root is not None:
            return self._is_running_as_root

        self._is_running_as_root = False
        if geteuid() == 0:
            self._is_running_as_root = True

        return self._is_running_as_root

    @property
    def sudo_available(self):
        """ Checks that sudo is available """
        if self._sudo_available is not None:
            return self._sudo_available

        if self.is_running_as_root:
            self._sudo_available = False
            return self._sudo_available

        try:
            subprocess.check_call(
                ['sudo', '-n', 'openvas', '-s'], stdout=subprocess.PIPE
            )
            self._sudo_available = True
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug(
                'It was not possible to call openvas with sudo. '
                'The scanner will run as non-root user. Reason %s',
                e,
            )
            self._sudo_available = False

        return self._sudo_available

    def check(self):
        """ Checks that openvas command line tool is found and
        is executable. """
        try:
            result = subprocess.check_output(
                ['openvas', '-V'], stderr=subprocess.STDOUT
            )
            result = result.decode('ascii')
        except OSError:
            # The command is not available
            return False

        if result is None:
            return False

        version = result.split('\n')
        if version[0].find('OpenVAS') < 0:
            return False

        self.parse_param()
        self.scanner_info['version'] = version[0]

        return True

    def update_progress(self, scan_id, target, current_host, msg):
        """ Calculate percentage and update the scan status of a host
        for the progress bar.
        Arguments:
            scan_id (uuid): Scan ID to identify the current scan process.
            target (str): Target to be updated with the calculated
                          scan progress.
            msg (str): String with launched and total plugins.
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
        self.set_scan_host_progress(scan_id, target, current_host, host_prog)

    def get_openvas_status(self, scan_id, target, current_host):
        """ Get all status entries from redis kb.
        Arguments:
            scan_id (uuid): Scan ID to identify the current scan.
            target (str): Target progress to be updated.
        """
        res = self.openvas_db.get_status()
        while res:
            self.update_progress(scan_id, target, current_host, res)
            res = self.openvas_db.get_status()

    def get_severity_score(self, oid):
        """ Return the severity score for the given oid.
        Arguments:
            oid (str): VT OID from which to get the severity vector
        Returns:
            The calculated cvss base value. None if there is no severity
            vector or severity type is not cvss base version 2.
        """
        severity_type = self.vts[oid]['severities'].get('severity_type')
        severity_vector = self.vts[oid]['severities'].get(
            'severity_base_vector'
        )

        if severity_type == "cvss_base_v2" and severity_vector:
            return CVSS.cvss_base_v2_value(severity_vector)

        return None

    def get_openvas_result(self, scan_id, current_host):
        """ Get all result entries from redis kb. """
        res = self.openvas_db.get_result()
        while res:
            msg = res.split('|||')
            roid = msg[3]
            rqod = ''
            rname = ''
            rhostname = msg[1] if msg[1] else ''
            host_is_dead = "Host dead" in msg[4]

            if not host_is_dead:
                if self.vts[roid].get('qod_type'):
                    qod_t = self.vts[roid].get('qod_type')
                    rqod = self.nvti.QOD_TYPES[qod_t]
                elif self.vts[roid].get('qod'):
                    rqod = self.vts[roid].get('qod')

                rname = self.vts[roid].get('name')

            if msg[0] == 'ERRMSG':
                self.add_scan_error(
                    scan_id,
                    host=current_host,
                    hostname=rhostname,
                    name=rname,
                    value=msg[4],
                    port=msg[2],
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
                rseverity = self.get_severity_score(roid)
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

            res = self.openvas_db.get_result()

    def get_openvas_timestamp_scan_host(self, scan_id, target):
        """ Get start and end timestamp of a host scan from redis kb. """
        timestamp = self.openvas_db.get_host_scan_scan_end_time()
        if timestamp:
            self.add_scan_log(
                scan_id, host=target, name='HOST_END', value=timestamp
            )
            return
        timestamp = self.openvas_db.get_host_scan_scan_start_time()
        if timestamp:
            self.add_scan_log(
                scan_id, host=target, name='HOST_START', value=timestamp
            )
            return

    def host_is_finished(self, scan_id):
        """ Check if the host has finished. """
        status = self.openvas_db.get_single_item('internal/%s' % scan_id)
        return status == 'finished'

    def target_is_finished(self, scan_id):
        """ Check if a target has finished. The scan id to be used is
        the scan id passed to the openvas, is not the global scan id."""
        ctx = self.openvas_db.kb_connect(dbnum=self.main_kbindex)
        scan_id = self.openvas_db.get_single_item(
            'internal/%s/globalscanid' % scan_id, ctx=ctx
        )
        status = self.openvas_db.get_single_item(
            'internal/%s' % scan_id, ctx=ctx
        )

        return status == 'finished' or status is None

    def scan_is_stopped(self, scan_id):
        """ Check if the parent process has received the stop_scan order.
        @in scan_id: ID to identify the scan to be stopped.
        @return 1 if yes, None in other case.
        """
        ctx = self.openvas_db.kb_connect(dbnum=self.main_kbindex)
        self.openvas_db.set_redisctx(ctx)
        status = self.openvas_db.get_single_item('internal/%s' % scan_id)
        return status == 'stop_all'

    def stop_scan_cleanup(
        self, global_scan_id
    ):  # pylint: disable=arguments-differ
        """ Set a key in redis to indicate the wrapper is stopped.
        It is done through redis because it is a new multiprocess
        instance and it is not possible to reach the variables
        of the grandchild process. Send SIGUSR2 to openvas to stop
        each running scan."""
        ctx = self.openvas_db.kb_connect()
        for current_kbi in range(0, self.openvas_db.max_dbindex):
            self.openvas_db.select_kb(ctx, str(current_kbi), set_global=True)
            scan_id = self.openvas_db.get_single_item(
                'internal/%s/globalscanid' % global_scan_id
            )
            if scan_id:
                self.openvas_db.set_single_item(
                    'internal/%s' % scan_id, ['stop_all']
                )
                ovas_pid = self.openvas_db.get_single_item('internal/ovas_pid')
                parent = None
                try:
                    parent = psutil.Process(int(ovas_pid))
                except psutil.NoSuchProcess:
                    logger.debug(
                        'Process with pid %s already stopped', ovas_pid
                    )
                except TypeError:
                    logger.debug(
                        'Scan with ID %s never started and stopped '
                        'unexpectedly',
                        scan_id,
                    )

                if parent:
                    cmd = ['openvas', '--scan-stop', scan_id]
                    if not self.is_running_as_root and self.sudo_available:
                        cmd = ['sudo', '-n'] + cmd

                    try:
                        subprocess.Popen(cmd, shell=False)
                    except OSError as e:
                        # the command is not available
                        logger.debug(
                            'Not possible to Stopping process: %s.' 'Reason %s',
                            parent,
                            e,
                        )
                        return False

                    logger.debug('Stopping process: %s', parent)
                    while parent:
                        try:
                            parent = psutil.Process(int(ovas_pid))
                        except psutil.NoSuchProcess:
                            parent = None

                self.openvas_db.release_db(current_kbi)

    def get_vts_in_groups(self, filters):
        """ Return a list of vts which match with the given filter.

        @input filters A list of filters. Each filter has key, operator and
                       a value. They are separated by a space.
                       Supported keys: family
        @return Return a list of vts which match with the given filter.
        """
        vts_list = list()
        families = dict()
        for oid in self.vts:
            family = self.vts[oid]['custom'].get('family')
            if family not in families:
                families[family] = list()
            families[family].append(oid)

        for elem in filters:
            key, value = elem.split('=')
            if key == 'family' and value in families:
                vts_list.extend(families[value])
        return vts_list

    def get_vt_param_type(self, vtid, vt_param_id):
        """ Return the type of the vt parameter from the vts dictionary. """

        vt_params_list = self.vts[vtid].get("vt_params")
        if vt_params_list.get(vt_param_id):
            return vt_params_list[vt_param_id]["type"]
        return None

    def get_vt_param_name(self, vtid, vt_param_id):
        """ Return the type of the vt parameter from the vts dictionary. """

        vt_params_list = self.vts[vtid].get("vt_params")
        if vt_params_list.get(vt_param_id):
            return vt_params_list[vt_param_id]["name"]
        return None

    @staticmethod
    def check_param_type(vt_param_value, param_type):
        """ Check if the value of a vt parameter matches with
        the type founded.
        """
        if param_type in [
            'entry',
            'file',
            'password',
            'radio',
            'sshlogin',
        ] and isinstance(vt_param_value, str):
            return None
        elif param_type == 'checkbox' and (
            vt_param_value == '0' or vt_param_value == '1'
        ):
            return None
        elif param_type == 'integer':
            try:
                int(vt_param_value)
            except ValueError:
                return 1
            return None

        return 1

    def process_vts(self, vts):
        """ Add single VTs and their parameters. """
        vts_list = []
        vts_params = []
        vtgroups = vts.pop('vt_groups')

        if vtgroups:
            vts_list = self.get_vts_in_groups(vtgroups)

        for vtid, vt_params in vts.items():
            if vtid not in self.vts.keys():
                logger.warning(
                    'The vt %s was not found and it will not be loaded.',
                    vtid,
                )
                continue
            vts_list.append(vtid)
            for vt_param_id, vt_param_value in vt_params.items():
                param_type = self.get_vt_param_type(vtid, vt_param_id)
                param_name = self.get_vt_param_name(vtid, vt_param_id)
                if not param_type or not param_name:
                    logger.debug(
                        'The vt parameter %s for %s could not be loaded.',
                        vt_param_id,
                        vtid,
                    )
                    continue
                if vt_param_id == '0':
                    type_aux = 'integer'
                else:
                    type_aux = param_type
                if self.check_param_type(vt_param_value, type_aux):
                    logger.debug(
                        'Expected %s type for parameter value %s',
                        type_aux,
                        str(vt_param_value),
                    )
                    continue
                if type_aux == 'checkbox':
                    vt_param_value = _from_bool_to_str(int(vt_param_value))
                param = [
                    "{0}:{1}:{2}:{3}".format(
                        vtid, vt_param_id, param_type, param_name
                    ),
                    str(vt_param_value),
                ]
                vts_params.append(param)
        return vts_list, vts_params

    @staticmethod
    def build_credentials_as_prefs(credentials):
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
                    + 'password:SNMP Community:'
                    + '{0}'.format(community)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':2:'
                    + 'entry:SNMPv3 Username:'
                    + '{0}'.format(username)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH + ':3:'
                    'password:SNMPv3 Password:' + '{0}'.format(password)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':4:'
                    + 'radio:SNMPv3 Authentication '
                    + 'Algorithm:{0}'.format(auth_algorithm)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':5:'
                    + 'password:SNMPv3 Privacy Password:'
                    + '{0}'.format(privacy_password)
                )
                cred_prefs_list.append(
                    OID_SNMP_AUTH
                    + ':6:'
                    + 'radio:SNMPv3 Privacy Algorithm:'
                    + '{0}'.format(privacy_algorithm)
                )

        return cred_prefs_list

    def exec_scan(self, scan_id, target):
        """ Starts the OpenVAS scanner for scan_id scan. """
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

        ports = self.get_scan_ports(scan_id, target)
        if not ports:
            self.add_scan_error(
                scan_id, name='', host=target, value='No port list defined.'
            )
            return 2

        # Get scan options
        options = self.get_scan_options(scan_id)
        prefs_val = []
        ctx = self.openvas_db.kb_new()
        self.openvas_db.set_redisctx(ctx)
        self.main_kbindex = self.openvas_db.db_index

        # To avoid interference between scan process during a parallel scanning
        # new uuid is used internally for each scan.
        openvas_scan_id = str(uuid.uuid4())
        self.openvas_db.add_single_item(
            'internal/%s' % openvas_scan_id, ['new']
        )
        self.openvas_db.add_single_item(
            'internal/%s/globalscanid' % scan_id, [openvas_scan_id]
        )
        self.openvas_db.add_single_item(
            'internal/scanid', [openvas_scan_id]
        )

        exclude_hosts = self.get_scan_exclude_hosts(scan_id, target)
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
        self.openvas_db.add_single_item(
            'internal/%s/scanprefs' % openvas_scan_id, prefs_val
        )

        # Store main_kbindex as global preference
        ov_maindbid = 'ov_maindbid|||%d' % self.main_kbindex
        self.openvas_db.add_single_item(
            'internal/%s/scanprefs' % openvas_scan_id, [ov_maindbid]
        )

        # Set target
        target_aux = 'TARGET|||%s' % target
        self.openvas_db.add_single_item(
            'internal/%s/scanprefs' % openvas_scan_id, [target_aux]
        )
        # Set port range
        port_range = 'port_range|||%s' % ports
        self.openvas_db.add_single_item(
            'internal/%s/scanprefs' % openvas_scan_id, [port_range]
        )

        # Set credentials
        credentials = self.get_scan_credentials(scan_id, target)
        if credentials:
            cred_prefs = self.build_credentials_as_prefs(credentials)
            self.openvas_db.add_single_item(
                'internal/%s/scanprefs' % openvas_scan_id, cred_prefs
            )

        # Set plugins to run
        nvts = self.get_scan_vts(scan_id)
        if nvts != '':
            nvts_list, nvts_params = self.process_vts(nvts)
            # Add nvts list
            separ = ';'
            plugin_list = 'plugin_set|||%s' % separ.join(nvts_list)
            self.openvas_db.add_single_item(
                'internal/%s/scanprefs' % openvas_scan_id, [plugin_list]
            )
            # Add nvts parameters
            for elem in nvts_params:
                item = '%s|||%s' % (elem[0], elem[1])
                self.openvas_db.add_single_item(
                    'internal/%s/scanprefs' % openvas_scan_id, [item]
                )
        else:
            self.openvas_db.release_db(self.main_kbindex)
            self.add_scan_error(
                scan_id, name='', host=target, value='No VTS to run.'
            )
            return 2

        cmd = ['openvas', '--scan-start', openvas_scan_id]
        if not self.is_running_as_root and self.sudo_available:
            cmd = ['sudo', '-n'] + cmd

        if self._niceness is not None:
            cmd = ['nice', '-n', self._niceness] + cmd

        logger.debug("Running scan with niceness %s", self._niceness)
        try:
            result = subprocess.Popen(cmd, shell=False)
        except OSError:
            # the command is not available
            return False

        ovas_pid = result.pid
        logger.debug('pid = %s', ovas_pid)
        self.openvas_db.add_single_item('internal/ovas_pid', [ovas_pid])

        # Wait until the scanner starts and loads all the preferences.
        while (
            self.openvas_db.get_single_item('internal/' + openvas_scan_id)
            == 'new'
        ):
            res = result.poll()
            if res and res < 0:
                self.stop_scan_cleanup(scan_id)
                msg = (
                    'It was not possible run the task %s, since openvas ended '
                    'unexpectedly with errors during launching.' % scan_id
                )
                logger.error(msg)
                return 1
            time.sleep(1)

        no_id_found = False
        while True:
            time.sleep(3)
            # Check if the client stopped the whole scan
            if self.scan_is_stopped(openvas_scan_id):
                return 1

            ctx = self.openvas_db.kb_connect(self.main_kbindex)
            self.openvas_db.set_redisctx(ctx)
            dbs = self.openvas_db.get_list_item('internal/dbindex')
            for i in list(dbs):
                if i == self.main_kbindex:
                    continue
                self.openvas_db.select_kb(ctx, str(i), set_global=True)
                id_aux = self.openvas_db.get_single_item('internal/scan_id')
                if not id_aux:
                    continue
                if id_aux == openvas_scan_id:
                    no_id_found = False
                    current_host = self.openvas_db.get_host_ip()
                    self.get_openvas_result(scan_id, current_host)
                    self.get_openvas_status(scan_id, target, current_host)
                    self.get_openvas_timestamp_scan_host(scan_id, current_host)
                    if self.host_is_finished(openvas_scan_id):
                        self.set_scan_host_finished(
                            scan_id, target, current_host
                        )
                        self.get_openvas_status(scan_id, target, current_host)
                        self.get_openvas_timestamp_scan_host(
                            scan_id, current_host
                        )
                        self.openvas_db.select_kb(
                            ctx, str(self.main_kbindex), set_global=False
                        )
                        self.openvas_db.remove_list_item('internal/dbindex', i)
                        self.openvas_db.release_db(i)

            # Scan end. No kb in use for this scan id
            if no_id_found and self.target_is_finished(scan_id):
                break
            no_id_found = True

        # Delete keys from KB related to this scan task.
        self.openvas_db.release_db(self.main_kbindex)
        return 1


def main():
    """ OSP openvas main function. """
    daemon_main('OSPD - openvas', OSPDopenvas)


if __name__ == '__main__':
    main()
