# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import json

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Union, Optional
from uuid import UUID, uuid4


class MessageType(Enum):
    RESULT = "result.scan"
    SCAN_STATUS = "scan.status"
    SCAN_START = "scan.start"


class Message:
    topic: str = None
    message_type: MessageType = None
    message_id: UUID = None
    group_id: str = None
    created: datetime = None

    def __init__(
        self,
        *,
        message_id: Optional[UUID] = None,
        group_id: Optional[str] = None,
        created: Optional[datetime] = None,
    ):
        self.message_id = message_id if message_id else uuid4()
        self.group_id = group_id if group_id else str(uuid4())
        self.created = created if created else datetime.utcnow()

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        message_type = MessageType(data.get('message_type'))
        if message_type != cls.message_type:
            raise ValueError(
                f"Invalid message type {message_type} for {cls.__name__}. "
                f"Must be {cls.message_type}.",
            )
        return {
            'message_id': UUID(data.get("message_id")),
            'group_id': data.get("group_id"),
            'created': datetime.fromtimestamp(
                float(data.get("created")), timezone.utc
            ),
        }

    def serialize(self) -> Dict[str, Union[int, str]]:
        return {
            "message_id": str(self.message_id),
            "message_type": self.message_type.value
            if self.message_type
            else None,
            "group_id": str(self.group_id),
            "created": self.created.timestamp(),
        }

    @classmethod
    def deserialize(cls, data: Dict[str, Union[int, str]]) -> "Message":
        kwargs = cls._parse(data)
        return cls(**kwargs)

    @classmethod
    def load(cls, payload: Union[str, bytes]) -> "Message":
        data = json.loads(payload)
        return cls.deserialize(data)

    def dump(self) -> str:
        return json.dumps(self.serialize())

    def __str__(self) -> str:
        return self.dump()
