# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import time
from datetime import datetime
from uuid import UUID

from unittest import TestCase, mock

from ospd_openvas.messages.result import ResultMessage
from ospd_openvas.messaging.mqtt import (
    MQTTDaemon,
    MQTTPublisher,
    MQTTSubscriber,
)


class MQTTPublisherTestCase(TestCase):
    def test_publish(self):
        client = mock.MagicMock()
        publisher = MQTTPublisher(client)

        created = datetime.fromtimestamp(1628512774)
        message_id = UUID('63026767-029d-417e-9148-77f4da49f49a')
        group_id = UUID('866350e8-1492-497e-b12b-c079287d51dd')
        message = ResultMessage(
            created=created,
            message_id=message_id,
            group_id=group_id,
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            port='42',
            uri='file://foo/bar',
        )

        publisher.publish(message)

        client.publish.assert_called_with(
            'scanner/scan/info',
            '{"message_id": "63026767-029d-417e-9148-77f4da49f49a", '
            '"message_type": "result.scan", '
            '"group_id": "866350e8-1492-497e-b12b-c079287d51dd", '
            '"created": 1628512774.0, '
            '"scan_id": "scan_1", '
            '"host_ip": "1.1.1.1", '
            '"host_name": "foo", '
            '"oid": "1.2.3.4.5", '
            '"value": "A Vulnerability has been found", '
            '"port": "42", '
            '"uri": "file://foo/bar", '
            '"result_type": "ALARM"}',
            qos=1,
        )


class MQTTSubscriberTestCase(TestCase):
    def test_subscribe(self):
        client = mock.MagicMock()
        callback = mock.MagicMock()
        callback.__name__ = "callback_name"

        subscriber = MQTTSubscriber(client)

        message = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            uri='file://foo/bar',
        )

        subscriber.subscribe(message, callback)

        client.subscribe.assert_called_with('scanner/scan/info', qos=1)


class MQTTDaemonTestCase(TestCase):
    def test_connect(self):
        client = mock.MagicMock()

        # pylint: disable=unused-variable
        daemon = MQTTDaemon(client)

    def test_run(self):
        client = mock.MagicMock(side_effect=1)
        daemon = MQTTDaemon(client)
        t_ini = time.time()

        daemon.run()
        # In some systems the spawn of the thread can take longer than expected.
        # Therefore, we wait until the thread is spawned or times out.
        while len(client.mock_calls) == 0 and time.time() - t_ini < 10:
            time.sleep(1)

        client.connect.assert_called_with()
        client.loop_start.assert_called_with()
