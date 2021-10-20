# Copyright (C) 2021 Greenbone Networks GmbH
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

from datetime import datetime
from enum import Enum
from typing import Dict, Union, Optional, Any
from uuid import UUID

from .message import Message, MessageType


class ScanStatus(Enum):
    FINISHED = "finished"
    REQUESTED = "requested"
    QUEUED = "queued"
    INIT = "init"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    INTERRUPTED = "interrupted"


class ScanStatusMessage(Message):
    message_type = MessageType.SCAN_STATUS
    topic = "scanner/status"

    def __init__(
        self,
        *,
        scan_id: str,
        host_ip: str,
        status: ScanStatus,
        message_id: Optional[UUID] = None,
        group_id: Optional[UUID] = None,
        created: Optional[datetime] = None,
    ):
        super().__init__(
            message_id=message_id, group_id=group_id, created=created
        )
        self.scan_id = scan_id
        self.host_ip = host_ip
        self.status = status

    def serialize(self) -> Dict[str, Union[int, str]]:
        message = super().serialize()
        message.update(
            {
                "scan_id": self.scan_id,
                "host_ip": self.host_ip,
                "status": self.status.value,
            }
        )
        return message

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        kwargs = super()._parse(data)
        kwargs.update(
            {
                "scan_id": data.get("scan_id"),
                "host_ip": data.get("host_ip"),
                "status": ScanStatus(data.get("status")),
            }
        )
        return kwargs
