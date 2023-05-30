# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from abc import ABC, abstractmethod
from typing import Callable, Type

from ..messages.message import Message


class Subscriber(ABC):
    """An Abstract Base Class (ABC) for subscribing to messages

    When updating to Python > 3.7 this should be converted into a
    typing.Protocol
    """

    @abstractmethod
    def subscribe(
        self, message_class: Type[Message], callback: Callable[[Message], None]
    ) -> None:
        raise NotImplementedError()
