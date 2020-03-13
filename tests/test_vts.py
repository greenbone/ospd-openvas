# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

from unittest import TestCase

from ospd.errors import OspdError
from ospd.vts import Vts
from hashlib import sha256


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
        # Python 3.5 doesn't ensure the order of the retuned keys
        self.assertIn(vt_id, ['id_1', 'id_2'])

        vt_id = next(it)
        self.assertIn(vt_id, ['id_1', 'id_2'])

        with self.assertRaises(StopIteration):
            next(it)

    def test_keys(self):
        vts = Vts()

        vts.add('id_1', name='foo')
        vts.add('id_2', name='bar')

        # use assertCountEqual for Python 3.5 because dict.keys order is
        # undefined
        self.assertCountEqual(vts.keys(), ['id_1', 'id_2'])

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
        vts = Vts()

        vts.add('id_2', name='bar', vt_modification_time='56789')
        vts.add('id_1', name='foo', vt_modification_time='01234')
        vts.calculate_vts_collection_hash()

        h = sha256()
        h.update("id_101234id_256789".encode('utf-8'))
        hash_test = h.hexdigest()

        self.assertEqual(hash_test, vts.sha256_hash)
