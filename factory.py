import arista
import cisco
import cumulus
import mikrotik
import yandc

class Client(object):
	def __new__(cls, *args, **kwargs):
		assert 'host' in kwargs, 'No host specified'

		grouped_kwargs = yandc.BaseClient.group_kwargs('snmp_', **kwargs)

		if not 'snmp_' in grouped_kwargs:
			raise Exception('No SNMP details specified')

		vendor = yandc.snmp.Client(kwargs['host'], **grouped_kwargs['snmp_']).enterprise()[0]

		if vendor == 'Arista':
			return arista.EOS_Client(*args, **kwargs)
		elif vendor == 'Cisco':
			return cisco.IOS_Client(*args, **kwargs)
		elif vendor == 'Cumulus':
			return cumulus.CL_Client(*args, **kwargs)
		elif vendor == 'Mikrotik':
			return mikrotik.ROS_Client(*args, **kwargs)

	def software_version(self):
		raise NotImplementedError('software_version()')

	def vendor(self):
		raise NotImplementedError('vendor()')
