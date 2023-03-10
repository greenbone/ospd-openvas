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

from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch
from typing import Dict, Optional

from ospd_openvas.gpg_sha_verifier import (
    ReloadConfiguration,
    create_verify,
    gpg_sha256sums,
    reload_sha256sums,
)


class GpgTest(TestCase):
    @patch("gnupg.GPG")
    @patch("pathlib.Path")
    def test_reload(self, gmock, pathmock: Path):
        def on_failure(_: Optional[Dict[str, str]]) -> Dict[str, str]:
            raise Exception("verification_failed")

        omock = Mock()
        emock = Mock()
        omock.__enter__ = Mock(return_value=emock)
        omock.__exit__ = Mock()
        pathmock.open.return_value = omock
        emock.readlines.side_effect = [["h  hi\n"], ["g  gude\n"]]
        emock.read.side_effect = [b"hi", b"", b"hi", b"", b"ih", b""]

        load = reload_sha256sums(
            ReloadConfiguration(
                hash_file=pathmock,
                on_verification_failure=on_failure,
                gpg=gmock,
            )
        )
        self.assertDictEqual(load(), {"h": "hi"})
        self.assertDictEqual(load(), {"h": "hi"})
        self.assertDictEqual(load(), {"g": "gude"})
        gmock.verify_file.side_effect = [False]
        with self.assertRaises(Exception):
            load()

    @patch("gnupg.GPG")
    @patch("pathlib.Path")
    def test_verifying(self, gmock, pathmock: Path):
        omock = Mock()
        emock = Mock()
        omock.__enter__ = Mock(return_value=emock)
        omock.__exit__ = Mock()
        pathmock.open.return_value = omock
        emock.readlines.side_effect = [["h  hi\n", "g  gude\n"]]
        success_result = gpg_sha256sums(pathmock, gmock)
        self.assertIsNotNone(success_result)
        self.assertDictEqual(success_result, {"h": "hi", "g": "gude"})
        gmock.verify_file.side_effect = [False]
        self.assertIsNone(gpg_sha256sums(pathmock, gmock))

    @patch("pathlib.Path")
    def test_verify_closure(self, pathmock):
        shas = (
            "98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4"
        )
        vsuccess = create_verify(lambda: {shas: "hi.txt"})
        omock = Mock()
        emock = Mock()
        omock.__enter__ = Mock(return_value=emock)
        omock.__exit__ = Mock()
        pathmock.open.return_value = omock
        emock.read.side_effect = [bytes("hi\n", "utf-8"), ""]
        pathmock.name = "hi.txt"
        self.assertTrue(vsuccess(pathmock))
        emock.read.side_effect = [bytes("hi\n", "utf-8"), ""]
        pathmock.name = "false.txt"
        self.assertFalse(vsuccess(pathmock))
        emock.read.side_effect = [bytes("hin", "utf-8"), ""]
        pathmock.name = "hi.txt"
        self.assertFalse(vsuccess(pathmock))
