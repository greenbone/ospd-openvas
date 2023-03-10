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

from datetime import datetime, timezone
from uuid import UUID

from unittest import TestCase

from ospd_openvas.messages.message import MessageType
from ospd_openvas.messages.result import ResultMessage, ResultType


class ResultMessageTestCase(TestCase):
    def test_constructor(self):
        message = ResultMessage(
            scan_id='scan_1',
            host_ip='1.1.1.1',
            host_name='foo',
            oid='1.2.3.4.5',
            value='A Vulnerability has been found',
            uri='file://foo/bar',
        )

        self.assertIsInstance(message.message_id, UUID)
        self.assertIsInstance(message.group_id, str)
        self.assertIsInstance(message.created, datetime)

        self.assertEqual(message.message_type, MessageType.RESULT)
        self.assertEqual(message.topic, 'scanner/scan/info')

        self.assertEqual(message.scan_id, 'scan_1')
        self.assertEqual(message.host_ip, '1.1.1.1')
        self.assertEqual(message.host_name, 'foo')
        self.assertEqual(message.oid, '1.2.3.4.5')
        self.assertEqual(message.value, 'A Vulnerability has been found')

        self.assertEqual(message.result_type, ResultType.ALARM)
        self.assertEqual(message.port, 'package')
        self.assertEqual(message.uri, 'file://foo/bar')

    def test_serialize(self):
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
            uri='file://foo/bar',
        )

        serialized = message.serialize()
        self.assertEqual(serialized['created'], 1628512774.0)
        self.assertEqual(
            serialized['message_id'], '63026767-029d-417e-9148-77f4da49f49a'
        )
        self.assertEqual(
            serialized['group_id'], '866350e8-1492-497e-b12b-c079287d51dd'
        )
        self.assertEqual(serialized['message_type'], 'result.scan')
        self.assertEqual(serialized['scan_id'], 'scan_1')
        self.assertEqual(serialized['host_ip'], '1.1.1.1')
        self.assertEqual(serialized['host_name'], 'foo')
        self.assertEqual(serialized['oid'], '1.2.3.4.5')
        self.assertEqual(serialized['value'], 'A Vulnerability has been found')
        self.assertEqual(serialized['uri'], 'file://foo/bar')
        self.assertEqual(serialized['port'], 'package')
        self.assertEqual(serialized['result_type'], 'ALARM')

    def test_deserialize(self):
        data = {
            'message_id': '63026767-029d-417e-9148-77f4da49f49a',
            'group_id': '866350e8-1492-497e-b12b-c079287d51dd',
            'created': 1628512774.0,
            'message_type': 'result.scan',
            'scan_id': 'scan_1',
            'host_ip': '1.1.1.1',
            'host_name': 'foo',
            'oid': '1.2.3.4.5',
            'value': 'A Vulnerability has been found',
            'uri': 'file://foo/bar',
            'port': 'package',
            'result_type': 'ALARM',
        }

        message = ResultMessage.deserialize(data)
        self.assertEqual(
            message.message_id, UUID('63026767-029d-417e-9148-77f4da49f49a')
        )
        self.assertEqual(
            message.group_id, '866350e8-1492-497e-b12b-c079287d51dd'
        )
        self.assertEqual(
            message.created,
            datetime.fromtimestamp(1628512774.0, tz=timezone.utc),
        )
        self.assertEqual(message.message_type, MessageType.RESULT)

        self.assertEqual(message.scan_id, 'scan_1')
        self.assertEqual(message.host_ip, '1.1.1.1')
        self.assertEqual(message.host_name, 'foo')
        self.assertEqual(message.oid, '1.2.3.4.5')
        self.assertEqual(message.value, 'A Vulnerability has been found')
        self.assertEqual(message.uri, 'file://foo/bar')
        self.assertEqual(message.port, 'package')
        self.assertEqual(message.result_type, ResultType.ALARM)

    def test_deserialize_invalid_message_type(self):
        data = {
            'message_id': '63026767-029d-417e-9148-77f4da49f49a',
            'group_id': '866350e8-1492-497e-b12b-c079287d51dd',
            'created': 1628512774.0,
            'message_type': 'scan.status',
            'scan_id': 'scan_1',
            'host_ip': '1.1.1.1',
            'host_name': 'foo',
            'oid': '1.2.3.4.5',
            'value': 'A Vulnerability has been found',
            'uri': 'file://foo/bar',
            'port': 'package',
            'result_type': 'ALARM',
        }
        with self.assertRaisesRegex(
            ValueError,
            "Invalid message type MessageType.SCAN_STATUS for "
            "ResultMessage. Must be MessageType.RESULT.",
        ):
            ResultMessage.deserialize(data)

    def test_deserialize_invalid_result_type(self):
        data = {
            'message_id': '63026767-029d-417e-9148-77f4da49f49a',
            'group_id': '866350e8-1492-497e-b12b-c079287d51dd',
            'created': 1628512774.0,
            'message_type': 'result.scan',
            'scan_id': 'scan_1',
            'host_ip': '1.1.1.1',
            'host_name': 'foo',
            'oid': '1.2.3.4.5',
            'value': 'A Vulnerability has been found',
            'uri': 'file://foo/bar',
            'port': 'package',
            'result_type': 'foo',
        }

        with self.assertRaisesRegex(
            ValueError, "'foo' is not a valid ResultType"
        ):
            ResultMessage.deserialize(data)
