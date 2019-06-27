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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
"""
Module for serving and streaming data
"""

import logging
import select
import socket
import ssl
import time

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional

from ospd.errors import OspdError

logger = logging.getLogger(__name__)


DEFAULT_STREAM_TIMEOUT = 2  # two seconds
DEFAULT_BUFSIZE = 1024


class Stream:
    def __init__(self, sock: socket.socket):
        self.socket = sock
        self.socket.settimeout(DEFAULT_STREAM_TIMEOUT)

    def close(self):
        """ Close the stream
        """
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

    def read(self, bufsize: Optional[int] = DEFAULT_BUFSIZE) -> bytes:
        """ Read at maximum bufsize data from the stream
        """
        data = self.socket.recv(bufsize)

        if not data:
            logger.debug('Client closed the connection')

        return data

    def write(self, data: bytes):
        """ Send data in chunks of DEFAULT_BUFSIZE to the client
        """
        b_start = 0
        b_end = DEFAULT_BUFSIZE

        while True:
            if b_end > len(data):
                self.socket.send(data[b_start:])
                break

            b_sent = self.socket.send(data[b_start:b_end])

            b_start = b_end
            b_end += b_sent


StreamCallbackType = Callable[[Stream], None]


class Server(ABC):
    @abstractmethod
    def bind(self):
        """ Start listening for incomming connections
        """

    @abstractmethod
    def select(
        self,
        stream_callback: StreamCallbackType,
        timeout: Optional[float] = None,
    ):
        """ Wait for incomming connections or until timeout is reached

        If a new client connects the stream_callback is called with a Stream

        Arguments:
            stream_callback (function): Callback function to be called when
                a stream is ready
            timeout (float): Timeout in seconds to wait for new streams
        """


class BaseServer(Server):
    def __init__(self):
        self.socket = None

    @abstractmethod
    def _accept(self) -> Stream:
        pass

    def select(
        self,
        stream_callback: StreamCallbackType,
        timeout: Optional[float] = None,
    ):
        inputs = [self.socket]

        readable, _, _ = select.select(inputs, [], inputs, timeout)

        # timeout has fired if readable is empty otherwise a new connection is
        # available
        if readable:
            stream = self._accept()
            stream_callback(stream)

    def close(self):
        if self.socket:
            self.socket.shutdown(socket.SHUT_RDWR)
            self.socket.close()


class UnixSocketServer(BaseServer):
    """ Server for accepting connections via a Unix domain socket
    """

    def __init__(self, socket_path: str):
        super().__init__()
        self.socket_path = Path(socket_path)

    def _cleanup_socket(self):
        if self.socket_path.exists():
            self.socket_path.unlink()

    def _create_parent_dirs(self):
        # create all parent directories for the socket path
        parent = self.socket_path.parent
        parent.mkdir(parents=True, exist_ok=True)

    def bind(self):
        self._cleanup_socket()
        self._create_parent_dirs()

        bindsocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            bindsocket.bind(str(self.socket_path))
        except socket.error:
            raise OspdError(
                "Couldn't bind socket on {}".format(self.socket_path)
            )

        logger.info(
            'Unix domain socket server listening on %s', self.socket_path
        )

        bindsocket.listen(0)
        bindsocket.setblocking(False)

        self.socket = bindsocket

    def _accept(self) -> Stream:
        new_socket, _addr = self.socket.accept()

        logger.debug("New connection from %s", self.socket_path)

        return Stream(new_socket)

    def close(self):
        super().close()

        self._cleanup_socket()


def validate_cacert_file(cacert: str):
    """ Check if provided file is a valid CA Certificate """
    try:
        context = ssl.create_default_context(cafile=cacert)
    except AttributeError:
        # Python version < 2.7.9
        return
    except IOError:
        raise OspdError('CA Certificate not found')

    try:
        not_after = context.get_ca_certs()[0]['notAfter']
        not_after = ssl.cert_time_to_seconds(not_after)
        not_before = context.get_ca_certs()[0]['notBefore']
        not_before = ssl.cert_time_to_seconds(not_before)
    except (KeyError, IndexError):
        raise OspdError('CA Certificate is erroneous')

    now = int(time.time())
    if not_after < now:
        raise OspdError('CA Certificate expired')

    if not_before > now:
        raise OspdError('CA Certificate not active yet')


class TlsServer(BaseServer):
    """ Server for accepting TLS encrypted connections via a TCP socket
    """

    def __init__(
        self,
        address: str,
        port: int,
        cert_file: str,
        key_file: str,
        ca_file: str,
    ):
        super().__init__()
        self.address = address
        self.port = port

        if not Path(cert_file).exists():
            raise OspdError('cert file {} not found'.format(cert_file))

        if not Path(key_file).exists():
            raise OspdError('key file {} not found'.format(key_file))

        if not Path(ca_file).exists():
            raise OspdError('CA file {} not found'.format(ca_file))

        validate_cacert_file(ca_file)

        # Despite the name, ssl.PROTOCOL_SSLv23 selects the highest
        # protocol version that both the client and server support. In modern
        # Python versions (>= 3.4) it supports TLS >= 1.0 with SSLv2 and SSLv3
        # being disabled. For Python > 3.5, PROTOCOL_SSLv23 is an alias for
        # PROTOCOL_TLS which should be used once compatibility with Python 3.5
        # is no longer desired.

        if hasattr(ssl, 'PROTOCOL_TLS'):
            protocol = ssl.PROTOCOL_TLS
        else:
            protocol = ssl.PROTOCOL_SSLv23

        self.tls_context = ssl.SSLContext(protocol)
        self.tls_context.verify_mode = ssl.CERT_REQUIRED

        self.tls_context.load_cert_chain(cert_file, keyfile=key_file)
        self.tls_context.load_verify_locations(ca_file)

    def _accept(self) -> Stream:
        new_socket, addr = self.socket.accept()

        logger.debug("New connection from" " %s:%s", addr[0], addr[1])

        ssl_socket = self.tls_context.wrap_socket(new_socket, server_side=True)

        return Stream(ssl_socket)

    def bind(self):
        bindsocket = socket.socket()
        try:
            bindsocket.bind((self.address, self.port))
        except socket.error:
            logger.error(
                "Couldn't bind socket on %s:%s", self.address, self.port
            )
            return None

        logger.info('TLS server listening on %s:%s', self.address, self.port)

        bindsocket.listen(0)
        bindsocket.setblocking(False)

        self.socket = bindsocket
