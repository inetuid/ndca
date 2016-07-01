"""Base Class
"""

__all__ = ['BaseClient']
__author__ = 'Matt Ryan'


class BaseClient(object):
	def __del__(self):
		self.disconnect()

	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		assert 'host' in kwargs, 'No host specified'

	def can_snmp(self):
		if hasattr(self, 'snmp_client'):
			return True
		return False

	def can_ssh(self):
		if hasattr(self, 'ssh_client'):
			return True
		return False

	def cli_command(self, command, *args, **kwargs):
		raise NotImplementedError

	def disconnect(self):
		if self.can_snmp():
			self.snmp_client.disconnect()
			del self.snmp_client
		if self.can_ssh():
			self.ssh_client.disconnect()
			del self.ssh_client

	@staticmethod
	def group_kwargs(*groups, **kwargs):
		grouped_kwargs = {}
		for key, value in kwargs.iteritems():
			for group in groups:
				group_length = len(group)
				if key.startswith(group):
					if not group in grouped_kwargs:
						grouped_kwargs[group] = {}
					grouped_kwargs[group][key[group_length:]] = value
		return grouped_kwargs

	def snmp_get(self, oid):
		if not self.can_snmp():
			raise Client_Exception('No SNMP client')
		return self.snmp_client.get_oid(self.snmp_client.format_oid(oid))

	def snmp_walk(self, oid):
		if not self.can_snmp():
			raise Client_Exception('No SNMP client')
		return self.snmp_client.walk_oids([self.snmp_client.format_oid(oid)])

	def software_version(self):
		raise NotImplementedError
