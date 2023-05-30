# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from abc import ABC, abstractmethod

from ..messages.message import Message


class Publisher(ABC):
    """An Abstract Base Class (ABC) for publishing Messages

    When updating to Python > 3.7 this should be converted into a
    typing.Protocol
    """

    @abstractmethod
    def publish(self, message: Message) -> None:
        raise NotImplementedError()
