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

""" Prepare the preferences to be used by OpenVAS """

import logging
import uuid
import binascii

from enum import IntEnum
from typing import Optional, Dict, List, Tuple
from base64 import b64decode

from ospd.scan import ScanCollection
from ospd_openvas.openvas import Openvas
from ospd_openvas.db import KbDB

logger = logging.getLogger(__name__)


OID_SSH_AUTH = "1.3.6.1.4.1.25623.1.0.103591"
OID_SMB_AUTH = "1.3.6.1.4.1.25623.1.0.90023"
OID_ESXI_AUTH = "1.3.6.1.4.1.25623.1.0.105058"
OID_SNMP_AUTH = "1.3.6.1.4.1.25623.1.0.105076"
OID_PING_HOST = "1.3.6.1.4.1.25623.1.0.100315"


class AliveTest(IntEnum):
    """ Alive Tests. """

    ALIVE_TEST_TCP_ACK_SERVICE = 1
    ALIVE_TEST_ICMP = 2
    ALIVE_TEST_ARP = 4
    ALIVE_TEST_CONSIDER_ALIVE = 8
    ALIVE_TEST_TCP_SYN_SERVICE = 16


def _from_bool_to_str(value: int) -> str:
    """ The OpenVAS scanner use yes and no as boolean values, whereas ospd
    uses 1 and 0."""
    return 'yes' if value == 1 else 'no'


class PreferenceHandler:
    def __init__(
        self, scan_id: str, kbdb: KbDB, scan_collection: ScanCollection
    ):
        self.scan_id = scan_id
        self.kbdb = kbdb
        self.scan_collection = scan_collection

        self._openvas_scan_id = None

        self._target_options = None

    @property
    def openvas_scan_id(self) -> str:
        """ Create the openvas scan id and store it in the redis kb.
        Return the openvas scan_id.
        """
        if self._openvas_scan_id is not None:
            return self._openvas_scan_id

        self._openvas_scan_id = str(uuid.uuid4())
        self.kbdb.add_scan_id(self.scan_id, self._openvas_scan_id)

        return self._openvas_scan_id

    @property
    def target_options(self) -> Dict:
        """ Return target options from Scan collection """
        if self._target_options is not None:
            return self._target_options

        self._target_options = self.scan_collection.get_target_options(
            self.scan_id
        )
        return self._target_options

    def get_vts_in_groups(
        self, filters: List[str], vts_cache: Dict[str, Dict],
    ) -> List[str]:
        """ Return a list of vts which match with the given filter.

        Arguments:
            filters A list of filters. Each filter has key, operator and
                    a value. They are separated by a space.
                    Supported keys: family

        Returns a list of vt oids which match with the given filter.
        """
        vts_list = list()
        families = dict()

        for oid in vts_cache:
            family = vts_cache[oid]['custom'].get('family')
            if family not in families:
                families[family] = list()

            families[family].append(oid)

        for elem in filters:
            key, value = elem.split('=')
            if key == 'family' and value in families:
                vts_list.extend(families[value])

        return vts_list

    def get_vt_param_type(
        self, vtid: str, vt_param_id: str, vts_cache: Dict[str, Dict],
    ) -> Optional[str]:
        """ Return the type of the vt parameter from the vts dictionary. """

        vt_params_list = vts_cache[vtid].get("vt_params")
        if vt_params_list.get(vt_param_id):
            return vt_params_list[vt_param_id]["type"]
        return None

    def get_vt_param_name(
        self, vtid: str, vt_param_id: str, vts_cache: Dict[str, Dict],
    ) -> Optional[str]:
        """ Return the type of the vt parameter from the vts dictionary. """

        vt_params_list = vts_cache[vtid].get("vt_params")
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

    def process_vts(
        self, vts: Dict[str, Dict[str, str]], vts_cache: Dict[str, Dict],
    ) -> Tuple[List[str], Dict[str, str]]:
        """ Add single VTs and their parameters. """
        vts_list = []
        vts_params = {}
        vtgroups = vts.pop('vt_groups')

        if vtgroups:
            vts_list = self.get_vts_in_groups(vtgroups, vts_cache)

        for vtid, vt_params in vts.items():
            if vtid not in vts_cache:
                logger.warning(
                    'The VT %s was not found and it will not be loaded.', vtid
                )
                continue

            vts_list.append(vtid)
            for vt_param_id, vt_param_value in vt_params.items():
                param_type = self.get_vt_param_type(
                    vtid, vt_param_id, vts_cache
                )
                param_name = self.get_vt_param_name(
                    vtid, vt_param_id, vts_cache
                )

                if not param_type or not param_name:
                    logger.debug(
                        'Missing type or name for VT parameter %s of %s. '
                        'It could not be loaded.',
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
                        'The VT parameter %s for %s could not be loaded. '
                        'Expected %s type for parameter value %s',
                        vt_param_id,
                        vtid,
                        type_aux,
                        str(vt_param_value),
                    )
                    continue

                if type_aux == 'checkbox':
                    vt_param_value = _from_bool_to_str(int(vt_param_value))

                vts_params[
                    "{0}:{1}:{2}:{3}".format(
                        vtid, vt_param_id, param_type, param_name
                    )
                ] = str(vt_param_value)

        return vts_list, vts_params

    def set_plugins(self, vts_cache: Dict[str, Dict],) -> bool:
        """ Get the plugin list to be launched from the Scan Collection
        and prepare the vts preferences. Store the data in the kb.
        """
        nvts = self.scan_collection.get_vts(self.scan_id)
        self.scan_collection.release_vts_list(self.scan_id)
        if nvts:
            nvts_list, nvts_params = self.process_vts(nvts, vts_cache)
            # Add nvts list
            separ = ';'
            plugin_list = 'plugin_set|||%s' % separ.join(nvts_list)
            self.kbdb.add_scan_preferences(self.openvas_scan_id, [plugin_list])

            # Add nvts parameters
            for key, val in nvts_params.items():
                item = '%s|||%s' % (key, val)
                self.kbdb.add_scan_preferences(self.openvas_scan_id, [item])

            nvts_params = None
            nvts_list = None
            item = None
            plugin_list = None
            nvts = None

            return True

        return False

    @staticmethod
    def build_alive_test_opt_as_prefs(target_options: Dict) -> List[str]:
        """ Parse the target options dictionary.
        @param credentials: Dictionary with the target options.

        @return A list with the target options in string format to be
                added to the redis KB.
        """
        target_opt_prefs_list = []
        if target_options and target_options.get('alive_test'):
            try:
                alive_test = int(target_options.get('alive_test'))
            except ValueError:
                logger.debug(
                    'Alive test settings not applied. '
                    'Invalid alive test value %s',
                    target_options.get('alive_test'),
                )
                return target_opt_prefs_list

            if alive_test < 1 or alive_test > 31:
                return target_opt_prefs_list

            if (
                alive_test & AliveTest.ALIVE_TEST_TCP_ACK_SERVICE
                or alive_test & AliveTest.ALIVE_TEST_TCP_SYN_SERVICE
            ):
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list.append(
                OID_PING_HOST
                + ':1:checkbox:'
                + 'Do a TCP ping|||'
                + '{0}'.format(value)
            )

            if (
                alive_test & AliveTest.ALIVE_TEST_TCP_SYN_SERVICE
                and alive_test & AliveTest.ALIVE_TEST_TCP_ACK_SERVICE
            ):
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list.append(
                OID_PING_HOST
                + ':2:checkbox:'
                + 'TCP ping tries also TCP-SYN ping|||'
                + '{0}'.format(value)
            )

            if (alive_test & AliveTest.ALIVE_TEST_TCP_SYN_SERVICE) and not (
                alive_test & AliveTest.ALIVE_TEST_TCP_ACK_SERVICE
            ):
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list.append(
                OID_PING_HOST
                + ':7:checkbox:'
                + 'TCP ping tries only TCP-SYN ping|||'
                + '{0}'.format(value)
            )

            if alive_test & AliveTest.ALIVE_TEST_ICMP:
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list.append(
                OID_PING_HOST
                + ':3:checkbox:'
                + 'Do an ICMP ping|||'
                + '{0}'.format(value)
            )

            if alive_test & AliveTest.ALIVE_TEST_ARP:
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list.append(
                OID_PING_HOST
                + ':4:checkbox:'
                + 'Use ARP|||'
                + '{0}'.format(value)
            )

            if alive_test & AliveTest.ALIVE_TEST_CONSIDER_ALIVE:
                value = "no"
            else:
                value = "yes"
            target_opt_prefs_list.append(
                OID_PING_HOST
                + ':5:checkbox:'
                + 'Mark unrechable Hosts as dead (not scanning)|||'
                + '{0}'.format(value)
            )

            # Also select a method, otherwise Ping Host logs a warning.
            if alive_test == AliveTest.ALIVE_TEST_CONSIDER_ALIVE:
                target_opt_prefs_list.append(
                    OID_PING_HOST + ':1:checkbox:' + 'Do a TCP ping|||yes'
                )
        return target_opt_prefs_list

    def set_alive_test_option(self):
        """ Set alive test option. Overwrite the scan config settings.
        Check if test_alive_hosts_only feature of openvas is active.
        If active, put ALIVE_TEST enum in preferences. """
        settings = Openvas.get_settings()
        if settings:
            test_alive_hosts_only = settings.get('test_alive_hosts_only')
            if test_alive_hosts_only:
                if self.target_options.get('alive_test'):
                    try:
                        alive_test = int(self.target_options.get('alive_test'))
                    except ValueError:
                        logger.debug(
                            'Alive test settings not applied. '
                            'Invalid alive test value %s',
                            self.target_options.get('alive_test'),
                        )
                    # Put ALIVE_TEST enum in db, this is then taken
                    # by openvas to determine the method to use
                    # for the alive test.
                    if alive_test >= 1 and alive_test <= 31:
                        item = 'ALIVE_TEST|||%s' % str(alive_test)
                        self.kbdb.add_scan_preferences(
                            self.openvas_scan_id, [item]
                        )
            else:
                alive_test_opt = self.build_alive_test_opt_as_prefs(
                    self.target_options
                )
                nvts_params = {}
                for elem in alive_test_opt:
                    key, val = elem.split("|||", 2)
                    nvts_params[key] = val

            # Add nvts parameters
            for key, val in nvts_params.items():
                item = '%s|||%s' % (key, val)
                self.kbdb.add_scan_preferences(self.openvas_scan_id, [item])

    def set_reverse_lookup_opt(self):
        """ Set reverse lookup options in the kb"""
        if self.target_options:
            _rev_lookup_only = int(
                self.target_options.get('reverse_lookup_only', '0')
            )
            rev_lookup_only = _from_bool_to_str(_rev_lookup_only)
            item = 'reverse_lookup_only|||%s' % (rev_lookup_only)
            self.kbdb.add_scan_preferences(self.openvas_scan_id, [item])

            _rev_lookup_unify = int(
                self.target_options.get('reverse_lookup_unify', '0')
            )
            rev_lookup_unify = _from_bool_to_str(_rev_lookup_unify)
            item = 'reverse_lookup_unify|||%s' % rev_lookup_unify
            self.kbdb.add_scan_preferences(self.openvas_scan_id, [item])

    def set_target(self):
        """ Get the target from the scan collection and set the target
        in the kb """

        target = self.scan_collection.get_host_list(self.scan_id)
        target_aux = 'TARGET|||%s' % target
        self.kbdb.add_scan_preferences(self.openvas_scan_id, [target_aux])

    def set_ports(self) -> str:
        """ Get the port list from the scan collection and store the list
        in the kb. """
        ports = self.scan_collection.get_ports(self.scan_id)
        port_range = 'port_range|||%s' % ports
        self.kbdb.add_scan_preferences(self.openvas_scan_id, [port_range])

        return ports

    def set_host_options(self):
        """ Get the excluded and finished hosts from the scan collection and
        stores the list of hosts that must not be scanned in the kb. """
        exclude_hosts = self.scan_collection.get_exclude_hosts(self.scan_id)

        # Get unfinished hosts, in case it is a resumed scan. And added
        # into exclude_hosts scan preference. Set progress for the finished ones
        # to 100%.
        finished_hosts = self.scan_collection.get_hosts_finished(self.scan_id)
        if finished_hosts:
            if exclude_hosts:
                finished_hosts_str = ','.join(finished_hosts)
                exclude_hosts = exclude_hosts + ',' + finished_hosts_str
            else:
                exclude_hosts = ','.join(finished_hosts)

        pref_val = "exclude_hosts|||" + exclude_hosts
        self.kbdb.add_scan_preferences(self.openvas_scan_id, [pref_val])

    def set_scan_params(self, ospd_params: Dict[str, Dict]):
        """ Get the scan parameters from the scan collection and store them
        in the kb. """
        options = self.scan_collection.get_options(self.scan_id)
        prefs_val = []

        for key, value in options.items():
            item_type = ''
            if key in ospd_params:
                item_type = ospd_params[key].get('type')
            if item_type == 'boolean':
                val = _from_bool_to_str(value)
            else:
                val = str(value)
            prefs_val.append(key + "|||" + val)

        self.kbdb.add_scan_preferences(self.openvas_scan_id, prefs_val)

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

    def set_credentials(self) -> bool:
        """ Get the credentials from the scan collection and store them
        in the kb. """
        credentials = self.scan_collection.get_credentials(self.scan_id)
        cred_prefs = self.build_credentials_as_prefs(credentials)

        if credentials and not cred_prefs:
            return False

        self.kbdb.add_scan_preferences(self.openvas_scan_id, cred_prefs)
        return True

    def set_main_kbindex(self, main_kbindex: int):
        """ Store main_kbindex as global preference in the
        kb, used by OpenVAS"""
        ov_maindbid = 'ov_maindbid|||%d' % main_kbindex
        self.kbdb.add_scan_preferences(self.openvas_scan_id, [ov_maindbid])
