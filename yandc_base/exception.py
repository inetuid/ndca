from snmp.exception import *
from ssh.exception import *

class ClientException(Exception):
    pass


class ClientError(ClientException):
    pass
