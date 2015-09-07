# $id$
# description:
# Test suites for Target manipulations.
#
# authors:
#   Benoit Allard <benoit.allard@greenbone.net>
#
# copyright:
# copyright (c) 2014 greenbone networks gmbh
#
# this program is free software; you can redistribute it and/or
# modify it under the terms of the gnu general public license
# as published by the free software foundation; either version 2
# of the license, or (at your option) any later version.
#
# this program is distributed in the hope that it will be useful,
# but without any warranty; without even the implied warranty of
# merchantability or fitness for a particular purpose.  see the
# gnu general public license for more details.
#
# you should have received a copy of the gnu general public license
# along with this program; if not, write to the free software
# foundation, inc., 51 franklin st, fifth floor, boston, ma 02110-1301 usa.

import unittest

from ospd.misc import target_str_to_list

class testTargetLists(unittest.TestCase):

    def test24Net(self):
        addresses = target_str_to_list('195.70.81.0/24')
        self.assertFalse(addresses is None)
        self.assertEqual(len(addresses), 254)
        for i in range(1, 255):
            self.assertTrue('195.70.81.%d' % i in addresses)
       
        
