# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# pylint: disable=bad-mcs-classmethod-argument, no-member

_has_init_subclass = hasattr(  # pylint: disable=invalid-name
    type, "__init_subclass__"
)

if not _has_init_subclass:

    class InitSubclassMeta(type):
        """Metaclass that implements PEP 487 protocol"""

        def __new__(cls, name, bases, ns, **kwargs):
            __init_subclass__ = ns.pop("__init_subclass__", None)
            if __init_subclass__:
                __init_subclass__ = classmethod(__init_subclass__)
                ns["__init_subclass__"] = __init_subclass__
            return super().__new__(cls, name, bases, ns, **kwargs)

        def __init__(cls, name, bases, ns, **kwargs):
            super().__init__(name, bases, ns)
            super_class = super(cls, cls)
            if hasattr(super_class, "__init_subclass__"):
                super_class.__init_subclass__.__func__(cls, **kwargs)

else:
    InitSubclassMeta = type  # type: ignore
