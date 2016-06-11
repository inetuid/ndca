import csv
import re
import snmp
import ssh
import vendor_base

have_rosapi = False

try:
	import rosapi
except ImportError:
	pass
else:
	have_rosapi = True

class Client(vendor_base.Client):
	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		super(Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs(['snmp_', 'ssh_', 'rosapi_'], **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				if not snmp_client.sysObjectID().startswith('1.3.6.1.4.1.14988.1'):
					raise ValueError('Not a Mikrotik device')
			except snmp.GetError:
				pass
			else:
				self.snmp_client = snmp_client

		if have_rosapi:
			pass

		if not self.can_rosapi():
			if not 'ssh_' in grouped_kwargs:
				grouped_kwargs['ssh_'] = {}
			if not 'username' in grouped_kwargs['ssh_'] and 'username' in kwargs:
				grouped_kwargs['ssh_']['username'] = kwargs['username']
			if not 'password' in grouped_kwargs['ssh_'] and 'password' in kwargs:
				grouped_kwargs['ssh_']['password'] = kwargs['password']

			shell_prompt = ssh.ShellPrompt(ssh.ShellPrompt.regexp_prompt(r'^\[[^\@]+\@[^\]]+\] > $'))

			if 'username' in grouped_kwargs['ssh_']:
				original_username = grouped_kwargs['ssh_']['username']
				grouped_kwargs['ssh_']['username'] += '+ct0h160w'

				if self.can_snmp():
					shell_prompt.add_prompt('[' + original_username + '@' + self.snmp_client.sysName() + '] > ')

			self.ssh_client = SSH_Client(kwargs['host'], **grouped_kwargs['ssh_'])
			self.shell = SSH_Shell(self.ssh_client, shell_prompt)

	def cli_command(self, *args, **kwargs):
		return self.ssh_command(*args, **kwargs)
		raise Exception('No CLI handler')

	def can_rosapi(self):
		if hasattr(self, '_rosapi'):
			return True
		return False

	def configure_via_cli(self, new_config):
		pass

	def disconnect(self):
		if self.can_rosapi():
			pass

		if self.can_ssh() and hasattr(self, 'shell'):
			self.shell.exit()
			del self.shell

		super(Client, self).disconnect()

		if hasattr(self, '_software_version'):
			del self._software_version

	def get_config(self, source=None, section=None):
		if section is not None:
			return self.ssh_command('/' + section + ' export verbose')
		return self.ssh_command('/export verbose')

	def get_interface_config(self, if_name):
		cli_output = self.ssh_command(':put [/interface get ' + if_name + ' type]')
		if cli_output == list():
			return cli_output

		if_type = cli_output[0]

		if if_type == 'ether':
			if_type = 'ethernet'
		elif if_type == 'pppoe-out':
			if_type = 'pppoe-client'

		return self.ssh_command(':put [/interface ' + if_type + ' print as-value where name="' + if_name + '"]')

	def in_configure_mode(self, *args, **kwargs):
		return False

	def software_version(self):
		if not hasattr(self, '_software_version'):
			self._software_version = None
			if self.can_snmp():
				self._software_version = self.snmp_client.os_version()
		return self._software_version

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise ValueError('No SSH client')
		if not hasattr(self, 'shell'):
			raise ValueError('No shell channel')
		return self.shell.command(*args, **kwargs)

	@staticmethod
	def values_decode(as_values):
		decoded_values = []

		temp_list = []
		if as_values.startswith('.id=*'):
			for as_value in as_values.split('.id=*'):
				if len(as_value):
					as_value = '.id=*' + as_value.rstrip(';')
				temp_list.append(as_value)
		else:
			temp_list.append(as_values)

		for row in csv.reader(temp_list, delimiter=';'):
			if len(row):
				temp_dict = {}
				for key_value in row:
					k, v = key_value.split('=', 2)
					temp_dict[unicode(k)] = v
				decoded_values.append(temp_dict)

		return decoded_values

	@staticmethod
	def vendor():
		return 'Mikrotik'


class SNMP_Client(snmp.Client):
	def fw_version(self):
		return self.get_oid(self.format_oid('1.3.6.1.4.1.14988.1.1.7.4.0'))

	def os_version(self):
		return str(self.get_oid(self.format_oid('1.3.6.1.4.1.14988.1.1.4.4.0')))


class SSH_Client(ssh.Client):
	pass


class SSH_Shell(ssh.Shell):
	def exit(self):
		return super(SSH_Shell, self).exit('/quit')

	def on_output_line(self, *args, **kwargs):
		output_line = re.sub(chr(0x1B) + r'\[9999B', '', super(SSH_Shell, self).on_output_line(*args, **kwargs))
		return output_line.lstrip('\r')
