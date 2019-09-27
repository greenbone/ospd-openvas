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
import socket
import ssl
import time
import os
import threading
import socketserver

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional

from ospd.errors import OspdError

logger = logging.getLogger(__name__)

DEFAULT_BUFSIZE = 1024


class Stream:
    def __init__(self, sock: socket.socket, stream_timeout: int):
        self.socket = sock
        self.socket.settimeout(stream_timeout)

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

            try:
                b_sent = self.socket.send(data[b_start:b_end])
            except socket.error as e:
                logger.error("Error sending data to the client. %s", e)
                return
            b_start = b_end
            b_end += b_sent


StreamCallbackType = Callable[[Stream], None]


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


def start_server(stream_callback, stream_timeout, newsocket, tls_ctx=None):
    """ Starts listening and creates a new thread for each new client
    connection.
    Arguments:
            stream_callback (function): Callback function to be called when
                a stream is ready
            newsocket (path to socket or socket tuple): The tuple with
                address and port or the path to the socket for unix domain
                sockets.
    Returns the created server object.
    """

    class ThreadedRequestHandler(socketserver.BaseRequestHandler):
        """ Class to handle the request."""

        def handle(self):
            if tls_ctx:
                logger.debug(
                    "New connection from" " %s:%s", newsocket[0], newsocket[1]
                )
                req_socket = tls_ctx.wrap_socket(self.request, server_side=True)
            else:
                req_socket = self.request
                logger.debug("New connection from %s", newsocket)

            stream = Stream(req_socket, stream_timeout)
            stream_callback(stream)

    class ThreadedUnixSockServer(
        socketserver.ThreadingMixIn, socketserver.UnixStreamServer
    ):
        pass

    class ThreadedTlsSockServer(
        socketserver.ThreadingMixIn, socketserver.TCPServer
    ):
        pass

    if tls_ctx:
        try:
            server = ThreadedTlsSockServer(newsocket, ThreadedRequestHandler)
        except OSError as e:
            logger.error(
                "Couldn't bind socket on %s:%s", newsocket[0], newsocket[1]
            )
            raise OspdError(
                "Couldn't bind socket on {}:{}. {}".format(
                    newsocket[0], str(newsocket[1]), e
                )
            )
    else:
        try:
            server = ThreadedUnixSockServer(
                str(newsocket), ThreadedRequestHandler
            )
        except OSError as e:
            logger.error("Couldn't bind socket on %s", str(newsocket))
            raise OspdError(
                "Couldn't bind socket on {}. {}".format(str(newsocket), e)
            )

    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    return server


class BaseServer(ABC):
    def __init__(self, stream_timeout):
        self.server = None
        self.stream_timeout = stream_timeout

    @abstractmethod
    def start(self, stream_callback: StreamCallbackType):
        """ Starts a server with capabilities to handle multiple client
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


class UnixSocketServer(BaseServer):
    """ Server for accepting connections via a Unix domain socket
    """

    def __init__(self, socket_path, socket_mode, stream_timeout: int):
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

        self.server = start_server(
            stream_callback, self.stream_timeout, self.socket_path
        )

        if self.socket_path.exists():
            os.chmod(str(self.socket_path), self.socket_mode)

    def close(self):
        super().close()
        self._cleanup_socket()


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

    def start(self, stream_callback: StreamCallbackType):
        self.server = start_server(
            stream_callback,
            self.stream_timeout,
            self.socket,
            tls_ctx=self.tls_context,
        )
