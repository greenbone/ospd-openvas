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

"""
Module for serving and streaming data
"""

import logging
import socket
import ssl
import time
import threading
import socketserver

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional, Tuple, Union

from ospd.errors import OspdError

logger = logging.getLogger(__name__)

DEFAULT_BUFSIZE = 1024


class Stream:
    def __init__(self, sock: socket.socket, stream_timeout: int):
        self.socket = sock
        self.socket.settimeout(stream_timeout)

    def close(self):
        """Close the stream"""
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            logger.debug(
                "Ignoring error while shutting down the connection. %s", e
            )

        self.socket.close()

    def read(self, bufsize: Optional[int] = DEFAULT_BUFSIZE) -> bytes:
        """Read at maximum bufsize data from the stream"""
        data = self.socket.recv(bufsize)

        if not data:
            logger.debug('Client closed the connection')

        return data

    def write(self, data: bytes) -> bool:
        """Send data in chunks of DEFAULT_BUFSIZE to the client"""
        b_start = 0
        b_end = DEFAULT_BUFSIZE
        ret_success = True

        while True:
            if b_end > len(data):
                try:
                    self.socket.send(data[b_start:])
                except (socket.error, BrokenPipeError) as e:
                    logger.error("Error sending data to the client. %s", e)
                    ret_success = False
                finally:
                    return ret_success  # pylint: disable=lost-exception

            try:
                b_sent = self.socket.send(data[b_start:b_end])
            except (socket.error, BrokenPipeError) as e:
                logger.error("Error sending data to the client. %s", e)
                return False

            b_start = b_end
            b_end += b_sent

        return ret_success


StreamCallbackType = Callable[[Stream], None]

InetAddress = Tuple[str, int]


def validate_cacert_file(cacert: str):
    """ Check if provided file is a valid CA Certificate """
    try:
        context = ssl.create_default_context(cafile=cacert)
    except AttributeError:
        # Python version < 2.7.9
        return
    except IOError:
        raise OspdError('CA Certificate not found') from None

    try:
        not_after = context.get_ca_certs()[0]['notAfter']
        not_after = ssl.cert_time_to_seconds(not_after)
        not_before = context.get_ca_certs()[0]['notBefore']
        not_before = ssl.cert_time_to_seconds(not_before)
    except (KeyError, IndexError):
        raise OspdError('CA Certificate is erroneous') from None

    now = int(time.time())
    if not_after < now:
        raise OspdError('CA Certificate expired')

    if not_before > now:
        raise OspdError('CA Certificate not active yet')


class RequestHandler(socketserver.BaseRequestHandler):
    """ Class to handle the request."""

    def handle(self):
        self.server.handle_request(self.request, self.client_address)


class BaseServer(ABC):
    def __init__(self, stream_timeout: int):
        self.server = None
        self.stream_timeout = stream_timeout

    @abstractmethod
    def start(self, stream_callback: StreamCallbackType):
        """Starts a server with capabilities to handle multiple client
        connections simultaneously.
        If a new client connects the stream_callback is called with a Stream

        Arguments:
            stream_callback (function): Callback function to be called when
                a stream is ready
        """

    def close(self):
        """ Shutdown the server"""
        self.server.shutdown()
        self.server.server_close()

    @abstractmethod
    def handle_request(self, request, client_address):
        """ Handle an incoming client request"""

    def _start_threading_server(self):
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True
        server_thread.start()


class SocketServerMixin:
    # Use daemon mode to circrumvent a memory leak
    # (reported at https://bugs.python.org/issue37193).
    #
    # Daemonic threads are killed immediately by the python interpreter without
    # waiting for until they are finished.
    #
    # Maybe block_on_close = True could work too.
    # In that case the interpreter waits for the threads to finish but doesn't
    # track them in the _threads list.
    daemon_threads = True

    def __init__(self, server: BaseServer, address: Union[str, InetAddress]):
        self.server = server
        super().__init__(address, RequestHandler, bind_and_activate=True)

    def handle_request(self, request, client_address):
        self.server.handle_request(request, client_address)


class ThreadedUnixSocketServer(
    SocketServerMixin, socketserver.ThreadingUnixStreamServer
):
    pass


class ThreadedTlsSocketServer(
    SocketServerMixin, socketserver.ThreadingTCPServer
):
    pass


class UnixSocketServer(BaseServer):
    """Server for accepting connections via a Unix domain socket"""

    def __init__(self, socket_path: str, socket_mode: str, stream_timeout: int):
        super().__init__(stream_timeout)
        self.socket_path = Path(socket_path)
        self.socket_mode = int(socket_mode, 8)

    def _cleanup_socket(self):
        if self.socket_path.exists():
            self.socket_path.unlink()

    def _create_parent_dirs(self):
        # create all parent directories for the socket path
        parent = self.socket_path.parent
        parent.mkdir(parents=True, exist_ok=True)

    def start(self, stream_callback: StreamCallbackType):
        self._cleanup_socket()
        self._create_parent_dirs()

        try:
            self.stream_callback = stream_callback
            self.server = ThreadedUnixSocketServer(self, str(self.socket_path))
            self._start_threading_server()
        except OSError as e:
            logger.error("Couldn't bind socket on %s", str(self.socket_path))
            raise OspdError(
                "Couldn't bind socket on {}. {}".format(
                    str(self.socket_path), e
                )
            ) from e

        if self.socket_path.exists():
            self.socket_path.chmod(self.socket_mode)

    def close(self):
        super().close()
        self._cleanup_socket()

    def handle_request(self, request, client_address):
        logger.debug("New request from %s", str(self.socket_path))

        stream = Stream(request, self.stream_timeout)
        self.stream_callback(stream)


class TlsServer(BaseServer):
    """Server for accepting TLS encrypted connections via a TCP socket"""

    def __init__(
        self,
        address: str,
        port: int,
        cert_file: str,
        key_file: str,
        ca_file: str,
        stream_timeout: int,
    ):
        super().__init__(stream_timeout)
        self.socket = (address, port)

        if not Path(cert_file).exists():
            raise OspdError('cert file {} not found'.format(cert_file))

        if not Path(key_file).exists():
            raise OspdError('key file {} not found'.format(key_file))

        if not Path(ca_file).exists():
            raise OspdError('CA file {} not found'.format(ca_file))

        validate_cacert_file(ca_file)

        protocol = ssl.PROTOCOL_SSLv23
        self.tls_context = ssl.SSLContext(protocol)
        self.tls_context.verify_mode = ssl.CERT_REQUIRED

        self.tls_context.load_cert_chain(cert_file, keyfile=key_file)
        self.tls_context.load_verify_locations(ca_file)

    def start(self, stream_callback: StreamCallbackType):
        try:
            self.stream_callback = stream_callback
            self.server = ThreadedTlsSocketServer(self, self.socket)
            self._start_threading_server()
        except OSError as e:
            logger.error(
                "Couldn't bind socket on %s:%s", self.socket[0], self.socket[1]
            )
            raise OspdError(
                "Couldn't bind socket on {}:{}. {}".format(
                    self.socket[0], str(self.socket[1]), e
                )
            ) from e

    def handle_request(self, request, client_address):
        logger.debug("New connection from %s", client_address)

        req_socket = self.tls_context.wrap_socket(request, server_side=True)

        stream = Stream(req_socket, self.stream_timeout)
        self.stream_callback(stream)
