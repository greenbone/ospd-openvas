# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Test suites for Target manipulations."""

import unittest
from unittest.mock import patch

from ospd.network import (
    target_str_to_list,
    get_hostname_by_address,
    is_valid_address,
    target_to_ipv4,
    socket,
)


class ConvertTargetListsTestCase(unittest.TestCase):
    def test_24_net(self):
        addresses = target_str_to_list('195.70.81.0/24')

        self.assertIsNotNone(addresses)
        self.assertEqual(len(addresses), 254)

        for i in range(1, 255):
            self.assertIn(f'195.70.81.{str(i)}', addresses)

    def test_bad_ipv4_cidr(self):
        addresses = target_str_to_list('195.70.81.0/32')
        self.assertIsNotNone(addresses)
        self.assertEqual(len(addresses), 0)

        addresses = target_str_to_list('195.70.81.0/31')
        self.assertIsNotNone(addresses)
        self.assertEqual(len(addresses), 0)

    def test_good_ipv4_cidr(self):
        addresses = target_str_to_list('195.70.81.0/30')
        self.assertIsNotNone(addresses)
        self.assertEqual(len(addresses), 2)

    def test_range(self):
        addresses = target_str_to_list('195.70.81.0-10')

        self.assertIsNotNone(addresses)
        self.assertEqual(len(addresses), 11)

        for i in range(0, 10):
            self.assertIn(f'195.70.81.{str(i)}', addresses)

    def test_target_str_with_trailing_comma(self):
        addresses = target_str_to_list(',195.70.81.1,195.70.81.2,')

        self.assertIsNotNone(addresses)
        self.assertEqual(len(addresses), 2)

        for i in range(1, 2):
            self.assertIn(f'195.70.81.{str(i)}', addresses)

    def test_get_hostname_by_address(self):
        with patch.object(socket, "getfqdn", return_value="localhost"):
            hostname = get_hostname_by_address('127.0.0.1')
            self.assertEqual(hostname, 'localhost')

        hostname = get_hostname_by_address('')
        self.assertEqual(hostname, '')

        hostname = get_hostname_by_address('127.0.0.1111')
        self.assertEqual(hostname, '')

    def test_is_valid_address(self):
        self.assertFalse(is_valid_address(None))
        self.assertFalse(is_valid_address(''))
        self.assertFalse(is_valid_address('foo'))
        self.assertFalse(is_valid_address('127.0.0.1111'))
        self.assertFalse(is_valid_address('127.0.0,1'))

        self.assertTrue(is_valid_address('127.0.0.1'))
        self.assertTrue(is_valid_address('192.168.0.1'))
        self.assertTrue(is_valid_address('::1'))
        self.assertTrue(is_valid_address('fc00::'))
        self.assertTrue(is_valid_address('fec0::'))
        self.assertTrue(
            is_valid_address('2001:0db8:85a3:08d3:1319:8a2e:0370:7344')
        )

    def test_target_to_ipv4(self):
        self.assertIsNone(target_to_ipv4('foo'))
        self.assertIsNone(target_to_ipv4(''))
        self.assertIsNone(target_to_ipv4('127,0,0,1'))
        self.assertIsNone(target_to_ipv4('127.0.0'))
        self.assertIsNone(target_to_ipv4('127.0.0.11111'))

        self.assertEqual(target_to_ipv4('127.0.0.1'), ['127.0.0.1'])
        self.assertEqual(target_to_ipv4('192.168.1.1'), ['192.168.1.1'])
