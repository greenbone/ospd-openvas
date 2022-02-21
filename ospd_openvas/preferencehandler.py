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

""" Prepare the preferences to be used by OpenVAS. Get the data from the scan
collection and store the data in a redis KB in the right format to be used by
OpenVAS. """

import logging
import binascii

from enum import IntEnum
from typing import Callable, Optional, Dict, List, Tuple
from base64 import b64decode

from ospd.scan import ScanCollection, ScanStatus
from ospd.ospd import BASE_SCANNER_PARAMS
from ospd.network import valid_port_list
from ospd_openvas.openvas import Openvas
from ospd_openvas.db import KbDB
from ospd_openvas.nvticache import NVTICache
from ospd_openvas.vthelper import VtHelper

logger = logging.getLogger(__name__)


OID_SSH_AUTH = "1.3.6.1.4.1.25623.1.0.103591"
OID_SMB_AUTH = "1.3.6.1.4.1.25623.1.0.90023"
OID_ESXI_AUTH = "1.3.6.1.4.1.25623.1.0.105058"
OID_SNMP_AUTH = "1.3.6.1.4.1.25623.1.0.105076"
OID_PING_HOST = "1.3.6.1.4.1.25623.1.0.100315"

BOREAS_ALIVE_TEST = "ALIVE_TEST"
BOREAS_ALIVE_TEST_PORTS = "ALIVE_TEST_PORTS"
BOREAS_SETTING_NAME = "test_alive_hosts_only"


class AliveTest(IntEnum):
    """Alive Tests."""

    ALIVE_TEST_SCAN_CONFIG_DEFAULT = 0
    ALIVE_TEST_TCP_ACK_SERVICE = 1
    ALIVE_TEST_ICMP = 2
    ALIVE_TEST_ARP = 4
    ALIVE_TEST_CONSIDER_ALIVE = 8
    ALIVE_TEST_TCP_SYN_SERVICE = 16


def alive_test_methods_to_bit_field(
    icmp: bool, tcp_syn: bool, tcp_ack: bool, arp: bool, consider_alive: bool
) -> int:
    """Internally a bit field is used as alive test. This function creates
    such a bit field out of the supplied alive test methods.
    """

    icmp_enum = AliveTest.ALIVE_TEST_ICMP if icmp else 0
    tcp_syn_enum = AliveTest.ALIVE_TEST_TCP_SYN_SERVICE if tcp_syn else 0
    tcp_ack_enum = AliveTest.ALIVE_TEST_TCP_ACK_SERVICE if tcp_ack else 0
    arp_enum = AliveTest.ALIVE_TEST_ARP if arp else 0
    consider_alive_enum = (
        AliveTest.ALIVE_TEST_CONSIDER_ALIVE if consider_alive else 0
    )

    bit_field = (
        icmp_enum | tcp_syn_enum | tcp_ack_enum | arp_enum | consider_alive_enum
    )
    return bit_field


def _from_bool_to_str(value: int) -> str:
    """The OpenVAS scanner use yes and no as boolean values, whereas ospd
    uses 1 and 0."""
    return 'yes' if value == 1 else 'no'


class PreferenceHandler:
    def __init__(
        self,
        scan_id: str,
        kbdb: KbDB,
        scan_collection: ScanCollection,
        nvticache: NVTICache,
        is_handled_by_notus: Optional[Callable[[str], bool]] = None,
    ):
        self.scan_id = scan_id
        self.kbdb = kbdb
        self.scan_collection = scan_collection

        self._target_options = None
        self._nvts_params = None

        self.nvti = nvticache
        if is_handled_by_notus:
            self.is_handled_by_notus = is_handled_by_notus
        elif not is_handled_by_notus and nvticache and nvticache.notus:
            self.is_handled_by_notus = nvticache.notus.exists
        else:
            self.is_handled_by_notus = lambda _: False
        self.errors = []

    def prepare_scan_id_for_openvas(self):
        """Create the openvas scan id and store it in the redis kb.
        Return the openvas scan_id.
        """
        self.kbdb.add_scan_id(self.scan_id)

    def get_error_messages(self) -> List:
        """Returns the Error List and reset it"""
        ret = self.errors
        self.errors = []
        return ret

    @property
    def target_options(self) -> Dict:
        """Return target options from Scan collection"""
        if self._target_options is not None:
            return self._target_options

        self._target_options = self.scan_collection.get_target_options(
            self.scan_id
        )
        return self._target_options

    def _get_vts_in_groups(
        self,
        filters: List[str],
    ) -> List[str]:
        """Return a list of vts which match with the given filter.

        Arguments:
            filters A list of filters. Each filter has key, operator and
                    a value. They are separated by a space.
                    Supported keys: family

        Returns a list of vt oids which match with the given filter.
        """
        vts_list = list()
        families = dict()

        oids = self.nvti.get_oids()

        for _, oid in oids:
            family = self.nvti.get_nvt_family(oid)
            if family not in families:
                families[family] = list()

            families[family].append(oid)

        for elem in filters:
            key, value = elem.split('=')
            if key == 'family' and value in families:
                vts_list.extend(families[value])

        return vts_list

    def _get_vt_param_type(self, vt: Dict, vt_param_id: str) -> Optional[str]:
        """Return the type of the vt parameter from the vts dictionary."""

        vt_params_list = vt.get("vt_params")
        if vt_params_list.get(vt_param_id):
            return vt_params_list[vt_param_id]["type"]
        return None

    def _get_vt_param_name(self, vt: Dict, vt_param_id: str) -> Optional[str]:
        """Return the type of the vt parameter from the vts dictionary."""

        vt_params_list = vt.get("vt_params")
        if vt_params_list.get(vt_param_id):
            return vt_params_list[vt_param_id]["name"]
        return None

    @staticmethod
    def check_param_type(vt_param_value: str, param_type: str) -> Optional[int]:
        """Check if the value of a vt parameter matches with
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

    def _process_vts(
        self,
        vts: Dict[str, Dict[str, str]],
    ) -> Tuple[List[str], Dict[str, str]]:
        """Add single VTs and their parameters."""
        vts_list = []
        vts_params = {}
        vtgroups = vts.pop('vt_groups')

        vthelper = VtHelper(self.nvti)

        if vtgroups:
            vts_list = self._get_vts_in_groups(vtgroups)

        counter = 0
        for vtid, vt_params in vts.items():
            counter += 1
            if counter % 500 == 0:
                if (
                    self.scan_collection.get_status(self.scan_id)
                    == ScanStatus.STOPPED
                ):
                    break

            # remove oids handled by notus
            if self.is_handled_by_notus(vtid):
                logger.debug('The VT %s is handled by notus. Ignoring.', vtid)
                continue

            vt = vthelper.get_single_vt(vtid)
            if not vt:
                logger.warning(
                    'The VT %s was not found and it will not be added to the '
                    'plugin scheduler.',
                    vtid,
                )
                continue

            vts_list.append(vtid)
            for vt_param_id, vt_param_value in vt_params.items():
                param_type = self._get_vt_param_type(vt, vt_param_id)
                param_name = self._get_vt_param_name(vt, vt_param_id)

                if vt_param_id > '0' and (not param_type or not param_name):
                    logger.debug(
                        'Missing type or name for VT parameter %s of %s. '
                        'This VT parameter will not be set.',
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
                        'The VT parameter %s for %s could not be set. '
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
                    f'{vtid}:{vt_param_id}:{param_type}:{param_name}'
                ] = str(vt_param_value)

        return vts_list, vts_params

    def prepare_plugins_for_openvas(self) -> bool:
        """Get the plugin list and it preferences from the Scan Collection.
        The plugin list is immediately stored in the kb.
        """
        nvts = self.scan_collection.get_vts(self.scan_id)

        if nvts:
            nvts_list, self._nvts_params = self._process_vts(nvts)
            # Add nvts list
            separ = ';'
            plugin_list = f'plugin_set|||{separ.join(nvts_list)}'
            self.kbdb.add_scan_preferences(self.scan_id, [plugin_list])

            return True

        return False

    def prepare_nvt_preferences(self):
        """Prepare the vts preferences. Store the data in the kb."""

        items_list = []
        counter = 0
        for key, val in self._nvts_params.items():
            items_list.append(f'{key}|||{val}')
            counter += 1
            if counter % 500 == 0:
                if (
                    self.scan_collection.get_status(self.scan_id)
                    == ScanStatus.STOPPED
                ):
                    break

        if items_list:
            self.kbdb.add_scan_preferences(self.scan_id, items_list)

    @staticmethod
    def build_alive_test_opt_as_prefs(
        target_options: Dict[str, str]
    ) -> Dict[str, str]:
        """Parse the target options dictionary.
        Arguments:
            target_options: Dictionary with the target options.

        Return:
            A dict with the target options related to alive test method
            in string format to be added to the redis KB.
        """
        target_opt_prefs_list = {}
        alive_test = None

        if target_options:
            # Alive test specified as bit field.
            alive_test = target_options.get('alive_test')
            # Alive test specified as individual methods.
            alive_test_methods = target_options.get('alive_test_methods')
            # alive_test takes precedence over alive_test_methods
            if alive_test is None and alive_test_methods:
                alive_test = alive_test_methods_to_bit_field(
                    icmp=target_options.get('icmp') == '1',
                    tcp_syn=target_options.get('tcp_syn') == '1',
                    tcp_ack=target_options.get('tcp_ack') == '1',
                    arp=target_options.get('arp') == '1',
                    consider_alive=target_options.get('consider_alive') == '1',
                )

        if target_options and alive_test:
            try:
                alive_test = int(alive_test)
            except ValueError:
                logger.debug(
                    'Alive test settings not applied. '
                    'Invalid alive test value %s',
                    target_options.get('alive_test'),
                )
                return target_opt_prefs_list

            # No alive test or wrong value, uses the default
            # preferences sent by the client.
            if alive_test < 1 or alive_test > 31:
                return target_opt_prefs_list

            if (
                alive_test & AliveTest.ALIVE_TEST_TCP_ACK_SERVICE
                or alive_test & AliveTest.ALIVE_TEST_TCP_SYN_SERVICE
            ):
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list[
                f'{OID_PING_HOST}:1:checkbox:Do a TCP ping'
            ] = value

            if (
                alive_test & AliveTest.ALIVE_TEST_TCP_SYN_SERVICE
                and alive_test & AliveTest.ALIVE_TEST_TCP_ACK_SERVICE
            ):
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list[
                f'{OID_PING_HOST}:2:checkbox:TCP ping tries also TCP-SYN ping'
            ] = value

            if (alive_test & AliveTest.ALIVE_TEST_TCP_SYN_SERVICE) and not (
                alive_test & AliveTest.ALIVE_TEST_TCP_ACK_SERVICE
            ):
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list[
                f'{OID_PING_HOST}:7:checkbox:TCP ping tries only TCP-SYN ping'
            ] = value

            if alive_test & AliveTest.ALIVE_TEST_ICMP:
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list[
                f'{OID_PING_HOST}:3:checkbox:Do an ICMP ping'
            ] = value

            if alive_test & AliveTest.ALIVE_TEST_ARP:
                value = "yes"
            else:
                value = "no"
            target_opt_prefs_list[f'{OID_PING_HOST}:4:checkbox:Use ARP'] = value

            if alive_test & AliveTest.ALIVE_TEST_CONSIDER_ALIVE:
                value = "no"
            else:
                value = "yes"
            target_opt_prefs_list[
                f'{OID_PING_HOST}:5:checkbox:Mark unrechable Hosts '
                'as dead (not scanning)'
            ] = value

        return target_opt_prefs_list

    def prepare_alive_test_option_for_openvas(self):
        """Set alive test option. Overwrite the scan config settings."""
        settings = Openvas.get_settings()
        if settings and (
            self.target_options.get('alive_test')
            or self.target_options.get('alive_test_methods')
        ):
            alive_test_opt = self.build_alive_test_opt_as_prefs(
                self.target_options
            )
            self._nvts_params.update(alive_test_opt)

    def prepare_boreas_alive_test(self):
        """Set alive_test for Boreas if boreas scanner config
        (BOREAS_SETTING_NAME) was set"""
        settings = Openvas.get_settings()
        alive_test = None
        alive_test_ports = None
        target_options = self.target_options

        if settings:
            boreas = settings.get(BOREAS_SETTING_NAME)
            if not boreas:
                return
        else:
            return

        if target_options:
            alive_test_ports = target_options.get('alive_test_ports')
            # Alive test was specified as bit field.
            alive_test = target_options.get('alive_test')
            # Alive test was specified as individual methods.
            alive_test_methods = target_options.get('alive_test_methods')
            # <alive_test> takes precedence over <alive_test_methods>
            if alive_test is None and alive_test_methods:
                alive_test = alive_test_methods_to_bit_field(
                    icmp=target_options.get('icmp') == '1',
                    tcp_syn=target_options.get('tcp_syn') == '1',
                    tcp_ack=target_options.get('tcp_ack') == '1',
                    arp=target_options.get('arp') == '1',
                    consider_alive=target_options.get('consider_alive') == '1',
                )

        if alive_test is not None:
            try:
                alive_test = int(alive_test)
            except ValueError:
                logger.debug(
                    'Alive test preference for Boreas not set. '
                    'Invalid alive test value %s.',
                    alive_test,
                )
                # Use default alive test as fall back
                alive_test = AliveTest.ALIVE_TEST_SCAN_CONFIG_DEFAULT
        # Use default alive test if no valid alive_test was provided
        else:
            alive_test = AliveTest.ALIVE_TEST_SCAN_CONFIG_DEFAULT

        # If a valid alive_test was set then the bit mask
        # has value between 31 (11111) and 1 (10000)
        if 1 <= alive_test <= 31:
            pref = f"{BOREAS_ALIVE_TEST}|||{alive_test}"
            self.kbdb.add_scan_preferences(self.scan_id, [pref])

        if alive_test == AliveTest.ALIVE_TEST_SCAN_CONFIG_DEFAULT:
            alive_test = AliveTest.ALIVE_TEST_ICMP
            pref = f"{BOREAS_ALIVE_TEST}|||{alive_test}"
            self.kbdb.add_scan_preferences(self.scan_id, [pref])

        # Add portlist if present. Validity is checked on Boreas side.
        if alive_test_ports is not None:
            pref = f"{BOREAS_ALIVE_TEST_PORTS}|||{alive_test_ports}"
            self.kbdb.add_scan_preferences(self.scan_id, [pref])

    def prepare_reverse_lookup_opt_for_openvas(self):
        """Set reverse lookup options in the kb"""
        if self.target_options:
            items = []
            _rev_lookup_only = int(
                self.target_options.get('reverse_lookup_only', '0')
            )
            rev_lookup_only = _from_bool_to_str(_rev_lookup_only)
            items.append(f'reverse_lookup_only|||{rev_lookup_only}')

            _rev_lookup_unify = int(
                self.target_options.get('reverse_lookup_unify', '0')
            )
            rev_lookup_unify = _from_bool_to_str(_rev_lookup_unify)
            items.append(f'reverse_lookup_unify|||{rev_lookup_unify}')

            self.kbdb.add_scan_preferences(self.scan_id, items)

    def prepare_target_for_openvas(self):
        """Get the target from the scan collection and set the target
        in the kb"""

        target = self.scan_collection.get_host_list(self.scan_id)
        target_aux = f'TARGET|||{target}'
        self.kbdb.add_scan_preferences(self.scan_id, [target_aux])

    def prepare_ports_for_openvas(self) -> str:
        """Get the port list from the scan collection and store the list
        in the kb."""
        ports = self.scan_collection.get_ports(self.scan_id)
        if not valid_port_list(ports):
            return False

        port_range = f'port_range|||{ports}'
        self.kbdb.add_scan_preferences(self.scan_id, [port_range])

        return ports

    def prepare_host_options_for_openvas(self):
        """Get the excluded and finished hosts from the scan collection and
        stores the list of hosts that must not be scanned in the kb."""
        exclude_hosts = self.scan_collection.get_exclude_hosts(self.scan_id)

        if exclude_hosts:
            pref_val = "exclude_hosts|||" + exclude_hosts
            self.kbdb.add_scan_preferences(self.scan_id, [pref_val])

    def prepare_scan_params_for_openvas(self, ospd_params: Dict[str, Dict]):
        """Get the scan parameters from the scan collection and store them
        in the kb.
        Arguments:
            ospd_params: Dictionary with the OSPD Params.
        """
        # Options which were supplied via the <scanner_params> XML element.
        options = self.scan_collection.get_options(self.scan_id)
        prefs_val = []

        for key, value in options.items():
            item_type = ''
            if key in ospd_params:
                item_type = ospd_params[key].get('type')
            else:
                if key not in BASE_SCANNER_PARAMS:
                    logger.debug(
                        "%s is a scanner only setting and should not be set "
                        "by the client. Setting needs to be included in "
                        "OpenVAS configuration file instead.",
                        key,
                    )
            if item_type == 'boolean':
                val = _from_bool_to_str(value)
            else:
                val = str(value)
            prefs_val.append(key + "|||" + val)

        if prefs_val:
            self.kbdb.add_scan_preferences(self.scan_id, prefs_val)

    def build_credentials_as_prefs(self, credentials: Dict) -> List[str]:
        """Parse the credential dictionary.
        Arguments:
            credentials: Dictionary with the credentials.

        Return:
            A list with the credentials in string format to be
            added to the redis KB.
        """
        cred_prefs_list = []
        for credential in credentials.items():
            service = credential[0]
            cred_params = credentials.get(service)
            cred_type = cred_params.get('type', '')
            username = cred_params.get('username', '')
            password = cred_params.get('password', '')

            # Check service ssh
            if service == 'ssh':
                # For ssh check the Port
                port = cred_params.get('port', '22')
                priv_username = cred_params.get('priv_username', '')
                priv_password = cred_params.get('priv_password', '')
                if not port:
                    port = '22'
                    warning = (
                        "Missing port number for ssh credentials. "
                        "Using default port 22."
                    )
                    logger.warning(warning)
                elif not port.isnumeric():
                    self.errors.append(
                        f"Port for SSH '{port}' is not a valid number."
                    )
                    continue
                elif int(port) > 65535 or int(port) < 1:
                    self.errors.append(
                        f"Port for SSH is out of range (1-65535): {port}"
                    )
                    continue
                # For ssh check the credential type
                if cred_type == 'up':
                    cred_prefs_list.append(
                        f'{OID_SSH_AUTH}:3:password:SSH password '
                        f'(unsafe!):|||{password}'
                    )
                elif cred_type == 'usk':
                    private = cred_params.get('private', '')
                    cred_prefs_list.append(
                        f'{OID_SSH_AUTH}:2:password:SSH key passphrase:|||'
                        f'{password}'
                    )
                    cred_prefs_list.append(
                        f'{OID_SSH_AUTH}:4:file:SSH private key:|||'
                        f'{private}'
                    )
                elif cred_type:
                    self.errors.append(
                        f"Unknown Credential Type for SSH: {cred_type}. "
                        "Use 'up' for Username + Password or 'usk' for "
                        "Username + SSH Key."
                    )
                    continue
                else:
                    self.errors.append(
                        "Missing Credential Type for SSH. Use 'up' for "
                        "Username + Password or 'usk' for Username + SSH Key."
                    )
                    continue
                cred_prefs_list.append(f'auth_port_ssh|||{port}')
                cred_prefs_list.append(
                    f'{OID_SSH_AUTH}:1:entry:SSH login name:|||{username}'
                )
                cred_prefs_list.append(
                    f'{OID_SSH_AUTH}:7:entry:SSH privilege login name:'
                    f'|||{priv_username}'
                )
                cred_prefs_list.append(
                    f'{OID_SSH_AUTH}:8:password:SSH privilege password:'
                    f'|||{priv_password}'
                )
            # Check servic smb
            elif service == 'smb':
                cred_prefs_list.append(
                    f'{OID_SMB_AUTH}:1:entry:SMB login:|||{username}'
                )
                cred_prefs_list.append(
                    f'{OID_SMB_AUTH}:2:password:SMB password:|||{password}'
                )
            # Check service esxi
            elif service == 'esxi':
                cred_prefs_list.append(
                    f'{OID_ESXI_AUTH}:1:entry:ESXi login name:|||{username}'
                )
                cred_prefs_list.append(
                    f'{OID_ESXI_AUTH}:2:password:ESXi login password:|||'
                    f'{password}'
                )
            # Check service snmp
            elif service == 'snmp':
                community = cred_params.get('community', '')
                auth_algorithm = cred_params.get('auth_algorithm', '')
                privacy_password = cred_params.get('privacy_password', '')
                privacy_algorithm = cred_params.get('privacy_algorithm', '')

                if not privacy_algorithm:
                    if privacy_password:
                        self.errors.append(
                            "When no privacy algorithm is used, the privacy"
                            + " password also has to be empty."
                        )
                        continue
                elif (
                    not privacy_algorithm == "aes"
                    and not privacy_algorithm == "des"
                ):
                    self.errors.append(
                        "Unknown privacy algorithm used: "
                        + privacy_algorithm
                        + ". Use 'aes', 'des' or '' (none)."
                    )
                    continue

                if not auth_algorithm:
                    self.errors.append(
                        "Missing authentication algorithm for SNMP."
                        + " Use 'md5' or 'sha1'."
                    )
                    continue
                elif (
                    not auth_algorithm == "md5" and not auth_algorithm == "sha1"
                ):
                    self.errors.append(
                        "Unknown authentication algorithm: "
                        + auth_algorithm
                        + ". Use 'md5' or 'sha1'."
                    )
                    continue

                cred_prefs_list.append(
                    f'{OID_SNMP_AUTH}:1:password:SNMP Community:|||{community}'
                )
                cred_prefs_list.append(
                    f'{OID_SNMP_AUTH}:2:entry:SNMPv3 Username:|||{username}'
                )
                cred_prefs_list.append(
                    f'{OID_SNMP_AUTH}:3:password:SNMPv3 Password:|||{password}'
                )
                cred_prefs_list.append(
                    f'{OID_SNMP_AUTH}:4:radio:SNMPv3 Authentication Algorithm:'
                    f'|||{auth_algorithm}'
                )
                cred_prefs_list.append(
                    f'{OID_SNMP_AUTH}:5:password:SNMPv3 Privacy Password:|||'
                    f'{privacy_password}'
                )
                cred_prefs_list.append(
                    f'{OID_SNMP_AUTH}:6:radio:SNMPv3 Privacy Algorithm:|||'
                    f'{privacy_algorithm}'
                )
            elif service:
                self.errors.append(
                    f"Unknown service type for credential: {service}"
                )
            else:
                self.errors.append("Missing service type for credential.")

        return cred_prefs_list

    def prepare_credentials_for_openvas(self) -> bool:
        """Get the credentials from the scan collection and store them
        in the kb."""
        logger.debug("Looking for given Credentials...")
        credentials = self.scan_collection.get_credentials(self.scan_id)
        if credentials:
            cred_prefs = self.build_credentials_as_prefs(credentials)
            if cred_prefs:
                self.kbdb.add_credentials_to_scan_preferences(
                    self.scan_id, cred_prefs
                )
                logger.debug("Credentials added to the kb.")
        else:
            logger.debug("No credentials found.")
        if credentials and not cred_prefs:
            return False

        return True

    def prepare_main_kbindex_for_openvas(self):
        """Store main_kbindex as global preference in the
        kb, used by OpenVAS"""
        ov_maindbid = f'ov_maindbid|||{self.kbdb.index}'
        self.kbdb.add_scan_preferences(self.scan_id, [ov_maindbid])
