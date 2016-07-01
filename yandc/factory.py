from .vendor_base import BaseClient
from .snmp import SNMP_Client
from yandc import *


class Client(object):
	def __new__(cls, *args, **kwargs):
		assert 'host' in kwargs, 'No host specified'

		grouped_kwargs = BaseClient.group_kwargs('snmp_', **kwargs)

		if not 'snmp_' in grouped_kwargs:
			raise Exception('No SNMP details specified')

		vendor = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_']).enterprise()[0]

		if vendor == 'Arista':
			return EOS_Client(*args, **kwargs)
		elif vendor == 'Cisco':
			return IOS_Client(*args, **kwargs)
		elif vendor == 'Cumulus':
			return CL_Client(*args, **kwargs)
		elif vendor == 'Mikrotik':
			return ROS_Client(*args, **kwargs)

	def software_version(self):
		raise NotImplementedError('software_version()')

	def vendor(self):
		raise NotImplementedError('vendor()')
