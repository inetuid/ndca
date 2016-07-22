class ClientException(Exception):
    pass


class ClientError(ClientException):
    pass


class DeviceMismatchError(ClientException):
    """Device doesn't match SNMP"""
    pass


class FileError(ClientException):
    """File related errors"""
    pass
