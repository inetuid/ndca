import sys
#
from .exception import *
from .vendor import *
from .ssh import Client as SSH_Client, Shell as SSH_Shell

def debug(func):
    def func_wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        sys.stderr.write(
            'DEBUG: {}({}, {}) = [{}][{}]\n'.format(
                func.__name__,
                args,
                kwargs,
                result,
                result.encode('hex') if isinstance(result, str) else ''
            )
        )
        return result
    return func_wrapper
