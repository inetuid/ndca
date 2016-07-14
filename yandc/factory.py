from .vendor_base import BaseClient
from .snmp import SNMP_Client
from yandc import *


class Client(object):
	def __new__(cls, *args, **kwargs):
		assert 'host' in kwargs, 'No host specified'

		grouped_kwargs = BaseClient.group_kwargs('snmp_', **kwargs)

		if 'snmp_' not in grouped_kwargs:
			raise Exception('No SNMP details specified')

		vendor, sys_object_id = SNMP_Client(
			kwargs['host'],
			**grouped_kwargs['snmp_']
		).enterprise()

		if EOS_Client.is_arista(sys_object_id):
			return EOS_Client(*args, **kwargs)
		elif vendor == 'Cisco':
			return IOS_Client(*args, **kwargs)
		elif vendor == 'Cumulus':
			return CL_Client(*args, **kwargs)
		elif ROS_Client.is_mikrotik(sys_object_id):
			return ROS_Client(*args, **kwargs)

	def software_version(self):
		raise NotImplementedError('software_version()')

	def vendor(self):
		raise NotImplementedError('vendor()')
