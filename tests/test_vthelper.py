# -*- coding: utf-8 -*-
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


from hashlib import sha256
from unittest import TestCase

from tests.dummydaemon import DummyDaemon
from tests.helper import assert_called_once

from ospd_openvas.vthelper import VtHelper


class VtHelperTestCase(TestCase):
    def test_get_single_vt(self):
        dummy = DummyDaemon()
        vthelper = VtHelper(dummy.nvti)
        res = vthelper.get_single_vt("1.3.6.1.4.1.25623.1.0.100061")

        assert_called_once(dummy.nvti.get_nvt_metadata)
        self.assertEqual("Mantis Detection", res.get('name'))

    def test_calculate_vts_collection_hash_no_params(self):
        dummy = DummyDaemon()
        vthelper = VtHelper(dummy.nvti)
        hash_out = vthelper.calculate_vts_collection_hash()

        vt_hash_str = (
            '1.3.6.1.4.1.25623.1.0.10006115339065651Data '
            + 'length :2Do not randomize the  order  in  which '
            + 'ports are scannedno'
        )

        vt_hash = sha256()
        vt_hash.update(vt_hash_str.encode('utf-8'))
        hash_test = vt_hash.hexdigest()

        self.assertEqual(hash_test, hash_out)

    def test_get_vt_iterator(self):
        dummy = DummyDaemon()
        vthelper = VtHelper(dummy.nvti)

        vt = ["1.3.6.1.4.1.25623.1.0.100061"]

        for key, _ in vthelper.get_vt_iterator():
            self.assertIn(key, vt)

    def test_get_vt_iterator_with_filter(self):
        dummy = DummyDaemon()
        vthelper = VtHelper(dummy.nvti)

        vt = ["1.3.6.1.4.1.25623.1.0.100061"]

        vtout = dummy.VTS["1.3.6.1.4.1.25623.1.0.100061"]

        for key, vt_dict in vthelper.get_vt_iterator(vt_selection=vt):
            self.assertIn(key, vt)
            for key2 in vtout:
                self.assertIn(key2, vt_dict)

    def test_get_vt_iterator_with_filter_no_vt(self):
        dummy = DummyDaemon()
        vthelper = VtHelper(dummy.nvti)
        dummy.nvti.get_nvt_metadata.return_value = None
        vt = ["1.3.6.1.4.1.25623.1.0.100065"]

        for _, values in vthelper.get_vt_iterator(vt_selection=vt):
            self.assertIs(values, None)
