__all__ = ['debug', 'EOS_Client', 'ISO_Client', 'XR_Client', 'CL_Client', 'ROS_Client']

import sys
#
from .arista import EOS_Client
from .cisco import IOS_Client, XR_Client
from .cumulus import CL_Client
from .mikrotik import ROS_Client

def debug(func):
	def func_wrapper(*args, **kwargs):
		result = func(*args, **kwargs)
		if isinstance(result, str):
			sys.stderr.write('DEBUG: %s(%s, %s) = [%s][%s]\n' % (func.__name__, args, kwargs, result, result.encode('hex')))
		else:
			sys.stderr.write('DEBUG: %s(%s, %s) = [%s]\n' % (func.__name__, args, kwargs, result))
		return result
	return func_wrapper
