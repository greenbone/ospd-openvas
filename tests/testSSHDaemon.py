import unittest

from ospd import ospd_ssh
from ospd.ospd_ssh import OSPDaemonSimpleSSH

class FakeFile(object):
    def __init__(self, content):
        self.content = content
    def readlines(self):
        return self.content.split('\n')

commands = None
class FakeSSHClient(object):
    def __init__(self):
        global commands
        commands = []
    def set_missing_host_key_policy(self, policy):
        pass
    def connect(self, **kwargs):
        pass
    def exec_command(self, cmd):
        commands.append(cmd)
        return None, FakeFile(''), None
    def close(self):
        pass

class FakeExceptions(object):
    AuthenticationException = None

class fakeparamiko(object):
    @staticmethod
    def SSHClient(*args):
        return FakeSSHClient(*args)

    @staticmethod
    def AutoAddPolicy():
        pass

    ssh_exception = FakeExceptions


class TestSSH(unittest.TestCase):

    def testNoParamiko(self):
        ospd_ssh.paramiko = None
        self.assertRaises(ImportError, OSPDaemonSimpleSSH, 'cert', 'key', 'ca')

    def testRunCommand(self):
        ospd_ssh.paramiko = fakeparamiko
        daemon = OSPDaemonSimpleSSH('cert', 'key', 'ca')
        scanid = daemon.create_scan(None, 'host.example.com', '80, 443',
                                    dict(port=5, ssh_timeout=15,
                                         username_password='dummy:pw'))
        res = daemon.run_command(scanid, 'host.example.com', 'cat /etc/passwd')
        self.assertTrue(isinstance(res, list))
        self.assertEqual(commands, ['cat /etc/passwd'])
