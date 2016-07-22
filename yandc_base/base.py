from .exception import ClientError


class Client(object):
	def __del__(self):
		self.disconnect()

	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		assert 'host' in kwargs, 'No host specified'
		self.snmp_client = None
		self.ssh_client = None

	def can_snmp(self):
		if hasattr(self, 'snmp_client'):
			if self.snmp_client is not None:
				return True
		return False

	def can_ssh(self):
		if hasattr(self, 'ssh_client'):
			if self.ssh_client is not None:
				return True
		return False

	def cli_command(self, command, *args, **kwargs):
		raise NotImplementedError

	def disconnect(self):
		if self.can_snmp():
			self.snmp_client.disconnect()
			del self.snmp_client
		if self.can_ssh():
			if self.ssh_client.is_active():
				self.ssh_client.disconnect()
			del self.ssh_client

	def snmp_get(self, oid):
		if not self.can_snmp():
			raise ClientError('No SNMP client')
		return self.snmp_client.get_oid(self.snmp_client.format_oid(oid))

	def snmp_walk(self, oid):
		if not self.can_snmp():
			raise ClientError('No SNMP client')
		return self.snmp_client.walk_oids([self.snmp_client.format_oid(oid)])

	def software_version(self):
		raise NotImplementedError

	def vendor(self):
		raise NotImplementedError
