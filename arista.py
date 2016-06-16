import json
import re
import yandc

have_pyeapi = False

try:
	import pyeapi
except ImportError:
	pass
else:
	have_pyeapi = True

class EOS_Client(yandc.vendor_base.Client):
	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		super(EOS_Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs('snmp_', 'ssh_', 'eapi_', **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				if not snmp_client.sysObjectID().startswith('1.3.6.1.4.1.30065.1'):
					raise ValueError('Not an Arista device')
			except yandc.snmp.GetError:
				pass
			else:
				self.snmp_client = snmp_client

		if have_pyeapi:
			if not 'eapi_' in grouped_kwargs:
				grouped_kwargs['eapi_'] = {}
			if not 'host' in grouped_kwargs['eapi_']:
				grouped_kwargs['eapi_']['host'] = kwargs['host']
			if not 'username' in grouped_kwargs['eapi_'] and 'username' in kwargs:
				grouped_kwargs['eapi_']['username'] = kwargs['username']
			if not 'password' in grouped_kwargs['eapi_'] and 'password' in kwargs:
				grouped_kwargs['eapi_']['password'] = kwargs['password']
			grouped_kwargs['eapi_']['return_node'] = True

			self._pyeapi_node = pyeapi.connect(**grouped_kwargs['eapi_'])

		if not self.can_eapi():
			if not 'ssh_' in grouped_kwargs:
				grouped_kwargs['ssh_'] = {}
			if not 'username' in grouped_kwargs['ssh_'] and 'username' in kwargs:
				grouped_kwargs['ssh_']['username'] = kwargs['username']
			if not 'password' in grouped_kwargs['ssh_'] and 'password' in kwargs:
				grouped_kwargs['ssh_']['password'] = kwargs['password']

			self.ssh_client = SSH_Client(kwargs['host'], **grouped_kwargs['ssh_'])

			shell_prompt = yandc.ssh.ShellPrompt(yandc.ssh.ShellPrompt.regexp_prompt(r'.+[#>]$'))
			shell_prompt.add_prompt(yandc.ssh.ShellPrompt.regexp_prompt(r'.+\(config[^\)]*\)#$'))

			self.shell = SSH_Shell(self.ssh_client, shell_prompt)
			self.shell.channel.set_combine_stderr(True)
			self.shell.command('terminal dont-ask')
			self.shell.command('terminal length 0')
			self.shell.command('no terminal monitor')
			self.shell.command('terminal width 160')

	def can_eapi(self):
		if hasattr(self, '_pyeapi_node'):
			return True
		return False

	def cli_command(self, *args, **kwargs):
		if self.can_eapi():
			return self.eapi_command(*args, **kwargs)
		elif self.can_ssh():
			return self.ssh_command(*args, **kwargs)
		raise Exception('No valid CLI handlers')

	def configure_via_cli(self, new_config):
		if self.can_eapi():
			try:
				config_output = self._pyeapi_node.config(new_config)
			except BaseException as error:
				print error
				return False
			else:
				for foo in config_output:
					if foo != dict():
						return False
			return True
		elif self.can_ssh():
			try:
				cli_output = self.ssh_command('configure terminal')
				if cli_output == list():
					self.in_configure_mode(True)
				else:
					raise ValueError(cli_output[0])

				for config_line in new_config:
					stripped_line = config_line.lstrip().rstrip()

					if stripped_line == 'end' or stripped_line == 'exit':
						warnings.warn('Skipping ' + config_line)
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
		if self.can_eapi():
			del self._pyeapi_node

		if self.can_ssh() and hasattr(self, 'shell'):
			self.shell.exit()
			del self.shell

		super(EOS_Client, self).disconnect()

		if hasattr(self, '_software_version'):
			del self._software_version

	@yandc.ssh.debug
	def eapi_command(self, *args, **kwargs):
		if self.can_eapi():
			if 'encoding' in kwargs and kwargs['encoding'] == 'json':
				kwargs['strict'] = True
				eapi_output = self._pyeapi_node.enable(*args, **kwargs)[0]

				if not eapi_output['encoding'] == 'json':
					raise TypeError('Enconding is not json')
				return eapi_output.get('result', None)
			else:
				kwargs['encoding'] = 'text'
				eapi_output = self._pyeapi_node.enable(*args, **kwargs)[0]

				if not eapi_output['encoding'] == 'text':
					raise TypeError('Enconding is not text')
				return eapi_output.get('result', list()).get('output', '').splitlines()
		return list()

	def get_config(self, source='running', section=None):
		if self.can_eapi():
			if section is not None:
				return self._pyeapi_node.get_config(config='{}-config'.format(source), params='section {}'.format(section))
			return self._pyeapi_node.get_config(config='{}-config'.format(source))
		else:
			config_command = 'show {}-config'.format(source)
			if section is not None:
				config_command += ' | section {}'.format(section)
			return self.ssh_command(config_command)

	def in_configure_mode(self, config_mode=None):
		if config_mode is not None:
			self._in_configure_flag = config_mode

		last_prompt = self.ssh_client.shell_last_prompt(self.shell)
		prompt_length = len(last_prompt)

		if prompt_length > 9:
			prompt_part = last_prompt[prompt_length - 9:]

			if config_mode:
				if prompt_part != '(config)#':
					raise ValueError('Mistmatch between in_configure_mode(' + str(config_mode) + ') and prompt [' + last_prompt + ']')
			else:
				if prompt_part == '(config)#':
					raise ValueError('Mistmatch between in_configure_mode(' + str(config_mode) + ') and prompt [' + last_prompt + ']')

		return getattr(self, '_in_configure_flag', False)

	def persist_configuration(self):
		if self.in_configure_mode():
			pass

		cli_output = self.cli_command('copy running-config startup-config')
		if cli_output[0] != 'Copy completed successfully.':
			raise ValueError(cli_output[0])
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
				self._software_version = self.snmp_client.os_version()
			elif self.can_eapi():
				self._software_version = self.eapi_command('show version', encoding='json').get('version', None)
			elif self.can_ssh():
				self._software_version = json.loads(''.join(self.ssh_command('show version | json'))).get('version', None)
		return self._software_version

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise ValueError('No SSH client')
		if not hasattr(self, 'shell'):
			raise ValueError('No shell channel')
		return self.shell.command(*args, **kwargs)

	@staticmethod
	def vendor():
		return 'Arista'


class SNMP_Client(yandc.snmp.Client):
	def os_version(self):
		re_match = re.match(r'Arista Networks EOS version (.+) running on an Arista Networks (.+)$', self.sysDescr())
		if re_match is not None:
			return re_match.groups(0)[0]
		return None


class SSH_Client(yandc.ssh.Client):
	pass


class SSH_Shell(yandc.ssh.Shell):
	def exit(self):
		return super(SSH_Shell, self).exit('logout')
