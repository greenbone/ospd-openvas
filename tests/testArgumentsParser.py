import logging
import unittest

from ospd.misc import create_args_parser, get_common_args


class testArgumentParser(unittest.TestCase):

    def setUp(self):
        self.parser = create_args_parser('Wrapper name')

    def testPortiInterval(self):
        self.assertRaises(SystemExit, get_common_args, self.parser, '--port=65536'.split())
        self.assertRaises(SystemExit, get_common_args, self.parser, '--port=0'.split())
        args = get_common_args(self.parser,
                               '--port=3353 -k /etc/passwd -c /etc/passwd --ca-file /etc/passwd'.split())
        self.assertEqual(3353, args['port'])

    def testPortasString(self):
        self.assertRaises(SystemExit, get_common_args, self.parser, '--port=abcd'.split())

    def testDefaultPort(self):
        args = get_common_args(self.parser,
                               '-k /etc/passwd -c /etc/passwd --ca-file /etc/passwd'.split())
        self.assertEqual(1234, args['port'])

    def testDefaultAddress(self):
        args = get_common_args(self.parser,
                               '-k /etc/passwd -c /etc/passwd --ca-file /etc/passwd'.split())
        self.assertEqual('0.0.0.0', args['address'])
        
    def testAddressParam(self):
        args = get_common_args(self.parser,
                               '-b 1.2.3.4 -k /etc/passwd -c /etc/passwd --ca-file /etc/passwd'.split())
        self.assertEqual('1.2.3.4', args['address'])

    def testDefaultLogLevel(self):
        args = get_common_args(self.parser,
                               '-k /etc/passwd -c /etc/passwd --ca-file /etc/passwd'.split())
        self.assertEqual(logging.WARNING, args['log_level'])
        
    def testCorrectDCLogLevel(self):
        args = get_common_args(self.parser,
                               '-L error -k /etc/passwd -c /etc/passwd --ca-file /etc/passwd'.split())
        self.assertEqual(logging.ERROR, args['log_level'])

    def testCorrectUCLogLevel(self):
        args = get_common_args(self.parser,
                               '-L INFO -k /etc/passwd -c /etc/passwd --ca-file /etc/passwd'.split())
        self.assertEqual(logging.INFO, args['log_level'])

    def testinCorrectLogLevel(self):
        self.assertRaises(SystemExit, get_common_args, self.parser,
                         '-L blah -k /etc/passwd -c /etc/passwd --ca-file /etc/passwd'.split())
