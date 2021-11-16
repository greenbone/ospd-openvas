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

""" Helper module for network related functions
"""

import binascii
import collections
import itertools
import logging
import re
import socket
import struct

from typing import List, Optional, Tuple

__LOGGER = logging.getLogger(__name__)


def target_to_ipv4(target: str) -> Optional[List]:
    """ Attempt to return a single IPv4 host list from a target string. """

    try:
        socket.inet_pton(socket.AF_INET, target)
        return [target]
    except socket.error:
        return None


def target_to_ipv6(target: str) -> Optional[List]:
    """ Attempt to return a single IPv6 host list from a target string. """

    try:
        socket.inet_pton(socket.AF_INET6, target)
        return [target]
    except socket.error:
        return None


def ipv4_range_to_list(start_packed, end_packed) -> Optional[List]:
    """ Return a list of IPv4 entries from start_packed to end_packed. """

    new_list = list()
    start = struct.unpack('!L', start_packed)[0]
    end = struct.unpack('!L', end_packed)[0]

    for value in range(start, end + 1):
        new_ip = socket.inet_ntoa(struct.pack('!L', value))
        new_list.append(new_ip)

    return new_list


def target_to_ipv4_short(target: str) -> Optional[List]:
    """ Attempt to return a IPv4 short range list from a target string. """

    splitted = target.split('-')
    if len(splitted) != 2:
        return None

    try:
        start_packed = socket.inet_pton(socket.AF_INET, splitted[0])
        end_value = int(splitted[1])
    except (socket.error, ValueError):
        return None

    # For subnet with mask lower than /24, ip addresses ending in .0 are
    # allowed.
    # The next code checks for a range starting with a A.B.C.0.
    # For the octet equal to 0, bytes() returns an empty binary b'',
    # which must be handle in a special way.
    _start_value = bytes(start_packed[3])
    if _start_value:
        start_value = int(binascii.hexlify(_start_value), 16)
    elif _start_value == b'':
        start_value = 0
    else:
        return None

    if end_value < 0 or end_value > 255 or end_value < start_value:
        return None

    end_packed = start_packed[0:3] + struct.pack('B', end_value)

    return ipv4_range_to_list(start_packed, end_packed)


def target_to_ipv4_cidr(target: str) -> Optional[List]:
    """ Attempt to return a IPv4 CIDR list from a target string. """

    splitted = target.split('/')
    if len(splitted) != 2:
        return None

    try:
        start_packed = socket.inet_pton(socket.AF_INET, splitted[0])
        block = int(splitted[1])
    except (socket.error, ValueError):
        return None

    if block <= 0 or block > 30:
        return None

    start_value = int(binascii.hexlify(start_packed), 16) >> (32 - block)
    start_value = (start_value << (32 - block)) + 1

    end_value = (start_value | (0xFFFFFFFF >> block)) - 1

    start_packed = struct.pack('!I', start_value)
    end_packed = struct.pack('!I', end_value)

    return ipv4_range_to_list(start_packed, end_packed)


def target_to_ipv6_cidr(target: str) -> Optional[List]:
    """ Attempt to return a IPv6 CIDR list from a target string. """

    splitted = target.split('/')
    if len(splitted) != 2:
        return None

    try:
        start_packed = socket.inet_pton(socket.AF_INET6, splitted[0])
        block = int(splitted[1])
    except (socket.error, ValueError):
        return None

    if block <= 0 or block > 126:
        return None

    start_value = int(binascii.hexlify(start_packed), 16) >> (128 - block)
    start_value = (start_value << (128 - block)) + 1

    end_value = (start_value | (int('ff' * 16, 16) >> block)) - 1

    high = start_value >> 64
    low = start_value & ((1 << 64) - 1)

    start_packed = struct.pack('!QQ', high, low)

    high = end_value >> 64
    low = end_value & ((1 << 64) - 1)

    end_packed = struct.pack('!QQ', high, low)

    return ipv6_range_to_list(start_packed, end_packed)


def target_to_ipv4_long(target: str) -> Optional[List]:
    """ Attempt to return a IPv4 long-range list from a target string. """

    splitted = target.split('-')
    if len(splitted) != 2:
        return None

    try:
        start_packed = socket.inet_pton(socket.AF_INET, splitted[0])
        end_packed = socket.inet_pton(socket.AF_INET, splitted[1])
    except socket.error:
        return None

    if end_packed < start_packed:
        return None

    return ipv4_range_to_list(start_packed, end_packed)


def ipv6_range_to_list(start_packed, end_packed) -> List:
    """ Return a list of IPv6 entries from start_packed to end_packed. """

    new_list = list()

    start = int(binascii.hexlify(start_packed), 16)
    end = int(binascii.hexlify(end_packed), 16)

    for value in range(start, end + 1):
        high = value >> 64
        low = value & ((1 << 64) - 1)
        new_ip = socket.inet_ntop(
            socket.AF_INET6, struct.pack('!2Q', high, low)
        )
        new_list.append(new_ip)

    return new_list


def target_to_ipv6_short(target: str) -> Optional[List]:
    """ Attempt to return a IPv6 short-range list from a target string. """

    splitted = target.split('-')
    if len(splitted) != 2:
        return None

    try:
        start_packed = socket.inet_pton(socket.AF_INET6, splitted[0])
        end_value = int(splitted[1], 16)
    except (socket.error, ValueError):
        return None

    start_value = int(binascii.hexlify(start_packed[14:]), 16)
    if end_value < 0 or end_value > 0xFFFF or end_value < start_value:
        return None

    end_packed = start_packed[:14] + struct.pack('!H', end_value)

    return ipv6_range_to_list(start_packed, end_packed)


def target_to_ipv6_long(target: str) -> Optional[List]:
    """ Attempt to return a IPv6 long-range list from a target string. """

    splitted = target.split('-')
    if len(splitted) != 2:
        return None

    try:
        start_packed = socket.inet_pton(socket.AF_INET6, splitted[0])
        end_packed = socket.inet_pton(socket.AF_INET6, splitted[1])
    except socket.error:
        return None

    if end_packed < start_packed:
        return None

    return ipv6_range_to_list(start_packed, end_packed)


def target_to_hostname(target: str) -> Optional[List]:
    """ Attempt to return a single hostname list from a target string. """

    if len(target) == 0 or len(target) > 255:
        return None

    if not re.match(r'^[\w.-]+$', target):
        return None

    return [target]


def target_to_list(target: str) -> Optional[List]:
    """ Attempt to return a list of single hosts from a target string. """

    # Is it an IPv4 address ?
    new_list = target_to_ipv4(target)
    # Is it an IPv6 address ?
    if not new_list:
        new_list = target_to_ipv6(target)
    # Is it an IPv4 CIDR ?
    if not new_list:
        new_list = target_to_ipv4_cidr(target)
    # Is it an IPv6 CIDR ?
    if not new_list:
        new_list = target_to_ipv6_cidr(target)
    # Is it an IPv4 short-range ?
    if not new_list:
        new_list = target_to_ipv4_short(target)
    # Is it an IPv4 long-range ?
    if not new_list:
        new_list = target_to_ipv4_long(target)
    # Is it an IPv6 short-range ?
    if not new_list:
        new_list = target_to_ipv6_short(target)
    # Is it an IPv6 long-range ?
    if not new_list:
        new_list = target_to_ipv6_long(target)
    # Is it a hostname ?
    if not new_list:
        new_list = target_to_hostname(target)

    return new_list


def target_str_to_list(target_str: str) -> Optional[List]:
    """Parses a targets string into a list of individual targets.
    Return a list of hosts, None if supplied target_str is None or
    empty, or an empty list in case of malformed target.
    """
    new_list = list()

    if not target_str:
        return None

    target_str = target_str.strip(',')

    for target in target_str.split(','):
        target = target.strip()
        target_list = target_to_list(target)

        if target_list:
            new_list.extend(target_list)
        else:
            __LOGGER.info("%s: Invalid target value", target)
            return []

    return list(collections.OrderedDict.fromkeys(new_list))


def resolve_hostname(hostname: str) -> Optional[str]:
    """ Returns IP of a hostname. """

    assert hostname
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def is_valid_address(address: str) -> bool:
    if not address:
        return False

    try:
        socket.inet_pton(socket.AF_INET, address)
    except OSError:
        # invalid IPv4 address
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except OSError:
            # invalid IPv6 address
            return False

    return True


def get_hostname_by_address(address: str) -> str:
    """ Returns hostname of an address. """

    if not is_valid_address(address):
        return ''

    try:
        hostname = socket.getfqdn(address)
    except (socket.gaierror, socket.herror):
        return ''

    if hostname == address:
        return ''

    return hostname


def port_range_expand(portrange: str) -> Optional[List]:
    """
    Receive a port range and expands it in individual ports.

    @input Port range.
    e.g. "4-8"

    @return List of integers.
    e.g. [4, 5, 6, 7, 8]
    """
    if not portrange or '-' not in portrange:
        __LOGGER.info("Invalid port range format")
        return None

    port_list = list()

    for single_port in range(
        int(portrange[: portrange.index('-')]),
        int(portrange[portrange.index('-') + 1 :]) + 1,
    ):
        port_list.append(single_port)

    return port_list


def port_str_arrange(ports: str) -> str:
    """Gives a str in the format (always tcp listed first).
    T:<tcp ports/portrange comma separated>U:<udp ports comma separated>
    """
    b_tcp = ports.find("T")
    b_udp = ports.find("U")

    if (b_udp != -1 and b_tcp != -1) and b_udp < b_tcp:
        return ports[b_tcp:] + ports[b_udp:b_tcp]

    return ports


def ports_str_check_failed(port_str: str) -> bool:
    """
    Check if the port string is well formed.
    Return True if fail, False other case.
    """

    pattern = r'[^TU:0-9, \-]'
    if (
        re.search(pattern, port_str)
        or port_str.count('T') > 1
        or port_str.count('U') > 1
        or port_str.count(':') < (port_str.count('T') + port_str.count('U'))
    ):
        return True

    return False


def ports_as_list(port_str: str) -> Tuple[Optional[List], Optional[List]]:
    """
    Parses a ports string into two list of individual tcp and udp ports.

    @input string containing a port list
    e.g. T:1,2,3,5-8 U:22,80,600-1024

    @return two list of sorted integers, for tcp and udp ports respectively.
    """
    if not port_str:
        __LOGGER.info("Invalid port value")
        return [None, None]

    if ports_str_check_failed(port_str):
        __LOGGER.info("{0}: Port list malformed.")
        return [None, None]

    tcp_list = list()
    udp_list = list()

    ports = port_str.replace(' ', '')

    b_tcp = ports.find("T")
    b_udp = ports.find("U")

    if ports[b_tcp - 1] == ',':
        ports = ports[: b_tcp - 1] + ports[b_tcp:]

    if ports[b_udp - 1] == ',':
        ports = ports[: b_udp - 1] + ports[b_udp:]

    ports = port_str_arrange(ports)

    tports = ''
    uports = ''
    # TCP ports listed first, then UDP ports
    if b_udp != -1 and b_tcp != -1:
        tports = ports[ports.index('T:') + 2 : ports.index('U:')]
        uports = ports[ports.index('U:') + 2 :]
    # Only UDP ports
    elif b_tcp == -1 and b_udp != -1:
        uports = ports[ports.index('U:') + 2 :]
    # Only TCP ports
    elif b_udp == -1 and b_tcp != -1:
        tports = ports[ports.index('T:') + 2 :]
    else:
        tports = ports

    if tports:
        for port in tports.split(','):
            if '-' in port:
                tcp_list.extend(port_range_expand(port))
            else:
                tcp_list.append(int(port))
        tcp_list.sort()

    if uports:
        for port in uports.split(','):
            if '-' in port:
                udp_list.extend(port_range_expand(port))
            else:
                udp_list.append(int(port))
        udp_list.sort()

    return (tcp_list, udp_list)


def get_tcp_port_list(port_str: str) -> Optional[List]:
    """ Return a list with tcp ports from a given port list in string format """
    return ports_as_list(port_str)[0]


def get_udp_port_list(port_str: str) -> Optional[List]:
    """ Return a list with udp ports from a given port list in string format """
    return ports_as_list(port_str)[1]


def port_list_compress(port_list: List) -> str:
    """ Compress a port list and return a string. """

    if not port_list or len(port_list) == 0:
        __LOGGER.info("Invalid or empty port list.")
        return ''

    port_list = sorted(set(port_list))
    compressed_list = []

    for _key, group in itertools.groupby(
        enumerate(port_list), lambda t: t[1] - t[0]
    ):
        group = list(group)

        if group[0][1] == group[-1][1]:
            compressed_list.append(str(group[0][1]))
        else:
            compressed_list.append(str(group[0][1]) + '-' + str(group[-1][1]))

    return ','.join(compressed_list)
