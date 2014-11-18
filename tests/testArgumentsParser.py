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
        
