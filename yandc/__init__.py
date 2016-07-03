__all__ = ['EOS_Client', 'IOS_Client', 'XR_Client', 'CL_Client', 'ROS_Client']

import sys
#
from .arista import EOS_Client
from .cisco import IOS_Client, XR_Client
from .cumulus import CL_Client
from .mikrotik import ROS_Client

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
