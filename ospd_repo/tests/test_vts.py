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

import logging

from hashlib import sha256
from unittest import TestCase
from unittest.mock import Mock

from collections import OrderedDict
from ospd.errors import OspdError
from ospd.vts import Vts


class VtsTestCase(TestCase):
    def test_add_vt(self):
        vts = Vts()

        vts.add('id_1', name='foo')

        self.assertEqual(len(vts.vts), 1)

    def test_add_duplicate_vt(self):
        vts = Vts()

        vts.add('id_1', name='foo')

        with self.assertRaises(OspdError):
            vts.add('id_1', name='bar')

        self.assertEqual(len(vts.vts), 1)

    def test_add_vt_with_empty_id(self):
        vts = Vts()

        with self.assertRaises(OspdError):
            vts.add(None, name='foo')

        with self.assertRaises(OspdError):
            vts.add('', name='foo')

    def test_add_vt_with_invalid_id(self):
        vts = Vts()

        with self.assertRaises(OspdError):
            vts.add('$$$_1', name='foo')

        self.assertEqual(len(vts.vts), 0)

    def test_contains(self):
        vts = Vts()

        vts.add('id_1', name='foo')

        self.assertIn('id_1', vts)

    def test_get(self):
        vts = Vts()

        vts.add('id_1', name='foo')
        vt = vts.get('id_1')

        self.assertIsNotNone(vt)
        self.assertEqual(vt['name'], 'foo')

        self.assertIsNone(vt.get('bar'))

    def test_iterator(self):
        vts = Vts()

        vts.add('id_1', name='foo')
        vts.add('id_2', name='bar')

        it = iter(vts)

        vt_id = next(it)
        self.assertIn(vt_id, ['id_1', 'id_2'])

        vt_id = next(it)
        self.assertIn(vt_id, ['id_1', 'id_2'])

        with self.assertRaises(StopIteration):
            next(it)

    def test_keys(self):
        vts = Vts()

        vts.add('id_1', name='foo')
        vts.add('id_2', name='bar')

        self.assertEqual(vts.keys(), ['id_1', 'id_2'])

    def test_getitem(self):
        vts = Vts()

        vts.add('id_1', name='foo')

        vt = vts['id_1']

        self.assertEqual(vt['name'], 'foo')

        with self.assertRaises(KeyError):
            vt = vts['foo']

    def test_copy(self):
        vts = Vts()

        vts.add('id_1', name='foo')
        vts.add('id_2', name='bar')

        vts2 = vts.copy()

        self.assertIsNot(vts, vts2)
        self.assertIsNot(vts.vts, vts2.vts)

        vta = vts.get('id_1')
        vtb = vts2.get('id_1')
        self.assertEqual(vta['name'], vtb['name'])
        self.assertIsNot(vta, vtb)

        vta = vts.get('id_2')
        vtb = vts2.get('id_2')
        self.assertEqual(vta['name'], vtb['name'])
        self.assertIsNot(vta, vtb)

    def test_calculate_vts_collection_hash(self):
        vts = Vts(storage=OrderedDict)

        vts.add(
            'id_1',
            name='foo',
            vt_modification_time='01234',
            vt_params={
                '0': {'id': '0', 'name': 'timeout', 'default': '20'},
                '1': {'id': '1', 'name': 'foo_pref:', 'default': 'bar_value'},
            },
        )
        vts.add('id_2', name='bar', vt_modification_time='56789')

        vts.calculate_vts_collection_hash()

        vt_hash = sha256()
        vt_hash.update(
            "id_1012340timeout201foo_pref:bar_valueid_256789".encode('utf-8')
        )
        hash_test = vt_hash.hexdigest()

        self.assertEqual(hash_test, vts.sha256_hash)

    def test_calculate_vts_collection_hash_no_params(self):
        vts = Vts(storage=OrderedDict)

        vts.add(
            'id_1',
            name='foo',
            vt_modification_time='01234',
            vt_params={
                '0': {'id': '0', 'name': 'timeout', 'default': '20'},
                '1': {'id': '1', 'name': 'foo_pref:', 'default': 'bar_value'},
            },
        )
        vts.add('id_2', name='bar', vt_modification_time='56789')

        vts.calculate_vts_collection_hash(include_vt_params=False)

        vt_hash = sha256()
        vt_hash.update("id_101234id_256789".encode('utf-8'))
        hash_test = vt_hash.hexdigest()

        self.assertEqual(hash_test, vts.sha256_hash)

    def test_calculate_vts_collection_hash_empty(self):
        vts = Vts()
        logging.Logger.debug = Mock()

        vts.calculate_vts_collection_hash()

        self.assertEqual(vts.sha256_hash, None)
        logging.Logger.debug.assert_called_with(  # pylint: disable=no-member
            "Error calculating VTs collection hash. Cache is empty"
        )
