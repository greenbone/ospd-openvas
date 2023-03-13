# Copyright (C) 2021 Greenbone AG
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

import json
import logging

from functools import partial
from socket import gaierror, timeout
from threading import Thread
from time import sleep
from typing import Callable, Type

import paho.mqtt.client as mqtt

from ..messages.message import Message

from .publisher import Publisher
from .subscriber import Subscriber

logger = logging.getLogger(__name__)

OSPD_OPENVAS_MQTT_CLIENT_ID = "ospd-openvas"

QOS_AT_LEAST_ONCE = 1


class MQTTClient(mqtt.Client):
    def __init__(
        self,
        mqtt_broker_address: str,
        mqtt_broker_port: int,
        client_id=OSPD_OPENVAS_MQTT_CLIENT_ID,
    ):
        self._mqtt_broker_address = mqtt_broker_address
        self._mqtt_broker_port = mqtt_broker_port

        super().__init__(client_id=client_id, protocol=mqtt.MQTTv5)

        self.enable_logger()

    def connect(
        self,
        host=None,
        port=None,
        keepalive=60,
        bind_address="",
        bind_port=0,
        clean_start=mqtt.MQTT_CLEAN_START_FIRST_ONLY,
        properties=None,
    ):
        if not host:
            host = self._mqtt_broker_address
        if not port:
            port = self._mqtt_broker_port

        return super().connect(
            host,
            port=port,
            keepalive=keepalive,
            bind_address=bind_address,
            bind_port=bind_port,
            clean_start=clean_start,
            properties=properties,
        )


class MQTTPublisher(Publisher):
    def __init__(self, client: MQTTClient):
        self._client = client

    def publish(self, message: Message) -> None:
        logger.debug('Publish message %s', message)
        self._client.publish(message.topic, str(message), qos=QOS_AT_LEAST_ONCE)


class MQTTSubscriber(Subscriber):
    def __init__(self, client: MQTTClient):
        self.client = client
        # Save the active subscriptions on subscribe() so we can resubscribe
        # after reconnect
        self.subscriptions: dict = {}

        self.client.on_connect = self.on_connect
        self.client.user_data_set(self.subscriptions)

    def subscribe(
        self, message_class: Type[Message], callback: Callable[[Message], None]
    ) -> None:
        func = partial(self._handle_message, message_class, callback)
        func.__name__ = callback.__name__

        logger.debug("Subscribing to topic %s", message_class.topic)

        self.client.subscribe(message_class.topic, qos=QOS_AT_LEAST_ONCE)
        self.client.message_callback_add(message_class.topic, func)

        self.subscriptions[message_class.topic] = func

    @staticmethod
    def on_connect(_client, _userdata, _flags, rc, _properties):
        if rc == 0:
            # If we previously had active subscription we subscribe to them
            # again because they got lost after a broker disconnect.
            # Userdata is set in __init__() and filled in subscribe()
            if _userdata:
                for topic, func in _userdata.items():
                    _client.subscribe(topic, qos=QOS_AT_LEAST_ONCE)
                    _client.message_callback_add(topic, func)

    @staticmethod
    def _handle_message(
        message_class: Type[Message],
        callback: Callable[[Message], None],
        _client,
        _userdata,
        msg: mqtt.MQTTMessage,
    ) -> None:
        logger.debug("Incoming message for topic %s", msg.topic)

        try:
            # Load message from payload
            message = message_class.load(msg.payload)
        except json.JSONDecodeError:
            logger.error(
                "Got MQTT message in non-json format for topic %s.", msg.topic
            )
            logger.debug("Got: %s", msg.payload)
            return
        except ValueError as e:
            logger.error(
                "Could not parse message for topic %s. Error was %s",
                msg.topic,
                e,
            )
            logger.debug("Got: %s", msg.payload)
            return

        callback(message)


class MQTTDaemon:
    """A class to start and stop the MQTT client"""

    def __init__(
        self,
        client: MQTTClient,
    ):
        self._client: MQTTClient = client

    def _try_connect_loop(self):
        while True:
            try:
                self._client.connect()
                self._client.loop_start()
                logger.info("Successfully connected to MQTT broker")
                return
            except (gaierror, ValueError) as e:
                logger.error(
                    "Could not connect to MQTT broker, error was: %s."
                    " Unable to get results from Notus.",
                    e,
                )
                return
            # ConnectionRefusedError - when mqtt declines connection
            # timeout - when address is not reachable
            # OSError - in container when address cannot be assigned
            except (ConnectionRefusedError, timeout, OSError) as e:
                logger.warning(
                    "Could not connect to MQTT broker, error was: %s."
                    " Trying again in 10s.",
                    e,
                )
                sleep(10)

    def run(self):
        Thread(target=self._try_connect_loop, daemon=True).start()
