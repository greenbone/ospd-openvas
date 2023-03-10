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

from ospd_openvas.messages.message import Message, MessageType


class MessageTestCase(TestCase):
    def test_default_constructor(self):
        message = Message()

        self.assertIsInstance(message.message_id, UUID)
        self.assertIsInstance(message.group_id, str)
        self.assertIsInstance(message.created, datetime)

    def test_serialize(self):
        created = datetime.fromtimestamp(1628512774)
        message_id = UUID('63026767-029d-417e-9148-77f4da49f49a')
        group_id = '866350e8-1492-497e-b12b-c079287d51dd'
        message = Message(
            message_id=message_id, group_id=group_id, created=created
        )

        serialized = message.serialize()
        self.assertEqual(serialized['created'], 1628512774.0)
        self.assertEqual(
            serialized['message_id'], '63026767-029d-417e-9148-77f4da49f49a'
        )
        self.assertEqual(
            serialized['group_id'], '866350e8-1492-497e-b12b-c079287d51dd'
        )
        self.assertIsNone(message.message_type)

    def test_deserialize(self):
        data = {
            'message_id': '63026767-029d-417e-9148-77f4da49f49a',
            'group_id': '866350e8-1492-497e-b12b-c079287d51dd',
            'created': 1628512774.0,
            'message_type': 'scan.start',
        }

        Message.message_type = MessageType.SCAN_START  # hack a message type

        message = Message.deserialize(data)
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

        Message.message_type = None

    def test_deserialize_no_message_type(self):
        data = {
            'message_id': '63026767-029d-417e-9148-77f4da49f49a',
            'group_id': '866350e8-1492-497e-b12b-c079287d51dd',
            'created': 1628512774.0,
        }

        with self.assertRaisesRegex(
            ValueError, "None is not a valid MessageType"
        ):
            Message.deserialize(data)

    def test_deserialize_unknown_message_type(self):
        data = {
            'message_id': '63026767-029d-417e-9148-77f4da49f49a',
            'group_id': '866350e8-1492-497e-b12b-c079287d51dd',
            'created': 1628512774.0,
            'message_type': 'foo',
        }

        with self.assertRaisesRegex(
            ValueError, "'foo' is not a valid MessageType"
        ):
            Message.deserialize(data)

    def test_to_str(self):
        created = datetime.fromtimestamp(1628512774)
        message_id = UUID('63026767-029d-417e-9148-77f4da49f49a')
        group_id = '866350e8-1492-497e-b12b-c079287d51dd'
        message = Message(
            message_id=message_id, group_id=group_id, created=created
        )

        self.assertEqual(
            str(message),
            '{"message_id": "63026767-029d-417e-9148-77f4da49f49a", '
            '"message_type": null, '
            '"group_id": "866350e8-1492-497e-b12b-c079287d51dd", '
            '"created": 1628512774.0}',
        )

    def test_load(self):
        payload = (
            '{"message_id": "63026767-029d-417e-9148-77f4da49f49a", '
            '"message_type": "scan.start", '
            '"group_id": "866350e8-1492-497e-b12b-c079287d51dd", '
            '"created": 1628512774.0}'
        )

        Message.message_type = MessageType.SCAN_START  # hack a message type
        message = Message.load(payload)

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

        Message.message_type = None
