"""Exceptions for the SSH package"""

class SSH_Exception(Exception):
    """SSH base exception class"""
    pass


class AuthenticationError(SSH_Exception):
    """Class for authentication errors"""
    pass


class ConnectError(SSH_Exception):
    """Class for connect errors"""
    pass


class GeneralError(SSH_Exception):
    """Class for general errors"""
    pass


class PromptError(SSH_Exception):
    """Class for prompt errors"""
    pass
