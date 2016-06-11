import re
import snmp
import ssh
import vendor_base

class IOS_Client(vendor_base.Client):
	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		super(IOS_Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs(['snmp_', 'ssh_'], **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client_ = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])

			try:
				if snmp_client_.enterprise()[0] != 'Cisco':
					raise ValueError('Not a Cisco device')
			except snmp.GetError:
				pass
			else:
				self.snmp_client = snmp_client_

		if 'ssh_' in grouped_kwargs:
			self.ssh_client = SSH_Client(kwargs['host'], **grouped_kwargs['ssh_'])
			shell_prompt = None
			self.shell_channel = self.ssh_client.shell(prompt=shell_prompt)

	def cli_command(self, *args, **kwargs):
		return self.ssh_command(*args, **kwargs)

	def configure_via_cli(self, new_config):
		try:
			cli_output = self.ssh_command('configure terminal')
			if cli_output == list():
				self.in_configure_mode(True)
			else:
				raise ValueError(cli_output[0])

			for config_line in new_config:
				stripped_line = config_line.lstrip().rstrip()

				if stripped_line == 'end' or stripped_line == 'exit':
					continue

				cli_output = self.ssh_command(stripped_line)
				if cli_output != list():
					raise ValueError(cli_output[0])
		finally:
			cli_output = self.ssh_command('end')
			if cli_output == list():
				self.in_configure_mode(False)

				return True
			else:
				raise ValueError(cli_output[0])

		return False

	def disconnect(self):
		if self.can_ssh() and hasattr(self, 'shell_channel'):
			self.ssh_client.shell_exit(self.shell_channel, 'logout')
			self.shell_channel.close()
			del self.shell_channel

		super(IOS_Client, self).disconnect()

		if hasattr(self, '_software_version'):
			del self._software_version

	def get_config(self, config_source='running', config_filter=None):
		return self.ssh_command('show ' + config_source + '-config')

	def get_interface_config(self, if_name):
		return self.ssh_command('show running-config interfaces ' + if_name)

	def in_configure_mode(self, *args, **kwargs):
		config_mode = super(Client, self).in_configure_mode(*args, **kwargs)

		last_prompt = self.ssh_client.shell_last_prompt(self.shell_channel)
		prompt_length = len(last_prompt)

		if prompt_length > 9:
			prompt_part = last_prompt[prompt_length - 9:]

			if config_mode:
				if prompt_part != '(config)#':
					raise ValueError('Mistmatch between in_configure_mode(' + str(config_mode) + ') and prompt [' + last_prompt + ']')
			else:
				if prompt_part == '(config)#':
					raise ValueError('Mistmatch between in_configure_mode(' + str(config_mode) + ') and prompt [' + last_prompt + ']')

		return config_mode
		
	def persist_configuration(self):
 		if self.in_configure_mode():
 			pass
 
 		cli_output = self.ssh_command('copy running-config startup-config')
 		if cli_output[0] != 'Copy completed successfully.':
			pass
# 			raise ValueError(cli_output[0])
 
 		return True

	def privilege_level(self):
		cli_output = self.ssh_command('show privilege')

		if cli_output[0][:27] != 'Current privilege level is ':
			raise ValueError(cli_output)

		return int(cli_output[0][27:])

	def software_version(self):
		if not hasattr(self, '_software_version'):
			self._software_version = None
			if self.can_snmp():
				self._software_version = self._snmp_client.os_version()
		return self._software_version

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise ValueError('No SSH client')
		if not hasattr(self, 'shell_channel'):
			raise ValueError('No shell channel')
		return self.ssh_client.shell_command(self.shell_channel, *args, **kwargs)

	@staticmethod
	def vendor():
		return 'Cisco_IOS'


class SNMP_Client(snmp.Client):
	def __init__(self, *args, **kwargs):
		super(SNMP_Client, self).__init__(*args, **kwargs)

	def os_version(self):
		re_match = re.match(r'^Arista Networks EOS version (\S+) ', self.sysDescr())
		if re_match:
			return re_match.groups(0)[0]

		return None


class SSH_Client(ssh.Client):
	def __init__(self, *args, **kwargs):
		super(SSH_Client, self).__init__(*args, **kwargs)

	def on_shell_output_line(self, *args, **kwargs):
		return super(SSH_Client, self).on_shell_output_line(*args, **kwargs).rstrip('\r').lstrip('\r')

	def shell(self, prompt=None, *args):
		generic_prompt = self.regexp_prompt(r'^.+[#>]$')

		if prompt is None:
			shell_channel = super(SSH_Client, self).shell(generic_prompt, *args)
		else:
			shell_channel = super(SSH_Client, self).shell(prompt, *args)
			self.shell_add_prompt(shell_channel, generic_prompt)

		self.shell_command(shell_channel, 'terminal length 0')
		self.shell_command(shell_channel, 'terminal no monitor')
		self.shell_command(shell_channel, 'terminal width 160')

		self.shell_add_prompt(shell_channel, self.regexp_prompt(r'^.+\(config[^\)]*\)#'))

		return shell_channel


class XR_Client(vendor_base.Client):
	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		pass

	def disconnect(self):
		pass

	@staticmethod
	def vendor():
		return 'Cisco_XR'
