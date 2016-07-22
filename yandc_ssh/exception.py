"""Exceptions for the SSH package"""

class SSH_Exception(Exception):
    """Base exception class"""
    pass


class AuthenticationError(SSH_Exception):
    """Problems with authentication"""
    pass


class ConnectError(SSH_Exception):
    """Client connect errors"""
    pass


class PromptError(SSH_Exception):
    """Prompt related errors"""
    pass


class RecvError(SSH_Exception):
    """Channel receive errors"""
    pass


class ResponseError(SSH_Exception):
    """CLI response errors"""
    pass


class SendError(SSH_Exception):
    """Channel send errors"""
    pass
