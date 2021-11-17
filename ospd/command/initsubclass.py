# Copyright (C) 2014-2021 Greenbone Networks GmbH
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
