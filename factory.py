import arista
import cisco
import cumulus
import mikrotik
import snmp
import vendor_base

class Client(object):
	def __new__(cls, *args, **kwargs):
		assert 'host' in kwargs, 'No host specified'

		grouped_kwargs = vendor_base.Client.group_kwargs(['snmp_'], **kwargs)

		if not 'snmp_' in grouped_kwargs:
			raise Exception('No SNMP details specified')

		vendor = snmp.Client(kwargs['host'], **grouped_kwargs['snmp_']).enterprise()[0]

		if vendor == 'Arista':
			return arista.Client(*args, **kwargs)
		elif vendor == 'Cisco':
			return cisco.Client(*args, **kwargs)
		elif vendor == 'Cumulus':
			return cumulus.Client(*args, **kwargs)
		elif vendor == 'Mikrotik':
			return mikrotik.Client(*args, **kwargs)

	def software_version(self):
		raise NotImplementedError('software_version()')

	def vendor(self):
		raise NotImplementedError('vendor()')
