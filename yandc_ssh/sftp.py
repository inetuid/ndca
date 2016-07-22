from .exception import *
from . import client


class Client(object):
    def __init__(self, ssh_client):
        assert isinstance(ssh_client, client.Client)
        self.ssh_client = ssh_client

    def sftp_client(self):
        return paramiko.SFTPClient.from_transport(self.ssh_client.paramiko_transport)
