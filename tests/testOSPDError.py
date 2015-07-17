import unittest

from ospd.ospd import OSPDError

class testOSPDError(unittest.TestCase):
    
    def testDefaultParams(self):
        e = OSPDError('message')
        self.assertEqual('message', e.message)
        self.assertEqual(400, e.status)
        self.assertEqual('osp', e.command)

    def testConstructor(self):
        e = OSPDError('message', 'command', '304')
        self.assertEqual('message', e.message)
        self.assertEqual('command', e.command)
        self.assertEqual('304', e.status)

    def testasXML(self):
        e = OSPDError('message')
        self.assertEqual(
            b'<osp_response status="400" status_text="message" />',
            e.as_xml())
