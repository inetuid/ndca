import re
import snmp
import ssh
import vendor_base

class Client(vendor_base.Client):
	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		super(Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs(['snmp_', 'ssh_'], **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				if not snmp_client.sysObjectID().startswith('1.3.6.1.4.1.40310'):
					raise Exception('Not a Cumulus device')
			except snmp.GetError:
				pass
			else:
				self.snmp_client = snmp_client

		if 'ssh_' in grouped_kwargs:
			if not 'username' in grouped_kwargs['ssh_'] and 'username' in kwargs:
				grouped_kwargs['ssh_']['username'] = kwargs['username']

			if not 'password' in grouped_kwargs['ssh_'] and 'password' in kwargs:
				grouped_kwargs['ssh_']['password'] = kwargs['password']

			self.ssh_client = SSH_Client(kwargs['host'], **grouped_kwargs['ssh_'])

			shell_prompt = ssh.ShellPrompt(ssh.ShellPrompt.regexp_prompt(r'^[^@]+@[^\$]+\$ '))
			if self.can_snmp() and 'username' in grouped_kwargs['ssh_']:
				shell_prompt.add_prompt(grouped_kwargs['ssh_']['username'] + '@' + self.snmp_client.sysName() + '$ ')

			self.shell = SSH_Shell(self.ssh_client, shell_prompt)

	def cli_command(self, *args, **kwargs):
		return self.ssh_command(*args, **kwargs)

	def configure_via_cli(self, new_config):
		return False

	def disconnect(self):
		if self.can_ssh() and hasattr(self, 'shell'):
			self.shell.exit()
			del self.shell

		super(Client, self).disconnect()

		if hasattr(self, '_software_version'):
			del self._software_version

	def get_config(self, config_source='running', config_filter=None):
		return list()

	def get_interface_config(self, if_name):
		return self.ssh_command('ifquery ' + if_name)

	def in_configure_mode(self, *args, **kwargs):
		return False
		
	def software_version(self):
		if not hasattr(self, '_software_version'):
			self._software_version = None
			if self.can_ssh():
				cli_output = self.ssh_command('lsb_release -r')
				if cli_output != list():
					self._software_version = cli_output[0][8:].lstrip().rstrip()
		return self._software_version

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise ValueError('No SSH client')
		if not hasattr(self, 'shell'):
			raise ValueError('No shell channel')
		return self.shell.command(*args, **kwargs)

	@staticmethod
	def vendor():
		return 'Cumulus'


class SNMP_Client(snmp.Client):
	pass


class SSH_Client(ssh.Client):
	pass


class SSH_Shell(ssh.Shell):
	def exit(self):
		return super(SSH_Shell, self).exit('logout')
