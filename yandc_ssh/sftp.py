from .exception import *
from .client import Client as SSH_Client


class Client(object):
    def __init__(self, ssh_client):
        assert isinstance(ssh_client, SSH_Client)

    def sftp_client(self):
        return paramiko.SFTPClient.from_transport(self.paramiko_transport)
