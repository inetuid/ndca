import json
#
import yandc_base as base
import yandc_ssh as ssh
#
try:
	from .snmp import Client as SNMP_Client
except ImportError:
	HAVE_SNMP = False
else:
	HAVE_SNMP = True

try:
	import pyeapi
except ImportError:
	HAVE_APILIB = False
else:
	HAVE_APILIB = True


class Client(base.Client):
	def __init__(self, *args, **kwargs):
		super(Client, self).__init__(*args, **kwargs)

		grouped_kwargs = base.Utils.group_kwargs('snmp_', 'ssh_', 'eapi_', **kwargs)

		if HAVE_SNMP and 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				sys_object_id = snmp_client.sysObjectID()
			except snmp.SNMP_Exception:
				pass
			else:
				if not self.is_arista(sys_object_id):
					raise base.DeviceMismatchError('Not an Arista device')
				self.snmp_client = snmp_client

		self.in_configure_mode = False

		if HAVE_APILIB:
			if 'eapi_' not in grouped_kwargs:
				grouped_kwargs['eapi_'] = {}
			if 'host' not in grouped_kwargs['eapi_']:
				grouped_kwargs['eapi_']['host'] = kwargs['host']
			if 'username' not in grouped_kwargs['eapi_'] and 'username' in kwargs:
				grouped_kwargs['eapi_']['username'] = kwargs['username']
			if 'password' not in grouped_kwargs['eapi_'] and 'password' in kwargs:
				grouped_kwargs['eapi_']['password'] = kwargs['password']
			grouped_kwargs['eapi_']['return_node'] = True

			self._pyeapi_node = pyeapi.connect(**grouped_kwargs['eapi_'])

		if not self.can_eapi():
			if 'ssh_' not in grouped_kwargs:
				grouped_kwargs['ssh_'] = {}
			if 'username' not in grouped_kwargs['ssh_'] and 'username' in kwargs:
				grouped_kwargs['ssh_']['username'] = kwargs['username']
			if 'password' not in grouped_kwargs['ssh_'] and 'password' in kwargs:
				grouped_kwargs['ssh_']['password'] = kwargs['password']

			self.ssh_client = ssh.Client(kwargs['host'], **grouped_kwargs['ssh_'])

			shell_prompt = ssh.ShellPrompt(ssh.ShellPrompt.regexp_prompt(r'.+[#>]$'))
			shell_prompt.add_prompt(ssh.ShellPrompt.regexp_prompt(r'.+\(config[^\)]*\)#$'))

			shell_args = {
				'combine_stderr': True,
				'terminal_width': 160,
				'initial_commands': [
					'terminal dont-ask',
					'terminal length 0',
					'no terminal monitor',
					'terminal width 160',
				],
			}
			self.ssh_shell = ssh.Shell(self.ssh_client, shell_prompt, optional_args=shell_args)
#			self.ssh_shell.channel.set_combine_stderr(True)
#			self.ssh_shell.command('terminal dont-ask')
#			self.ssh_shell.command('terminal length 0')
#			self.ssh_shell.command('no terminal monitor')
#			self.ssh_shell.command('terminal width 160')

	def can_eapi(self):
		if hasattr(self, '_pyeapi_node'):
			return True
		return False

	def cli_command(self, *args, **kwargs):
		if self.can_eapi():
			return self.eapi_command(*args, **kwargs)
		elif self.can_ssh():
			return self.ssh_command(*args, **kwargs)
		raise base.ClientError('No valid CLI handlers')

	def configure_via_cli(self, new_config):
		configured_okay = True
		if self.can_eapi():
			try:
				config_output = self._pyeapi_node.config(new_config)
			except BaseException as error:
				configured_okay = False
				print error
			else:
				for output_line in config_output:
					if output_line != {}:
						configured_okay = False
			return configured_okay
		elif self.can_ssh():
			try:
				cli_output = self.ssh_command('configure terminal')
				if cli_output == []:
					self.in_configure_mode = True
				else:
					raise base.ClientError(cli_output[0])

				for config_line in new_config:
					stripped_line = config_line.strip()
					if stripped_line in ['end', 'exit']:
						continue

					cli_output = self.ssh_command(stripped_line)
					if cli_output != []:
						configured_okay = False
#						raise base.ClientError(cli_output[0])
			except BaseException as error:
				configured_okay = False
			finally:
				cli_output = self.ssh_command('end')
				if cli_output == []:
					self.in_configure_mode = False
				else:
					configured_okay = False
#					raise base.ClientError(cli_output[0])
		return configured_okay

	def disconnect(self):
		if self.can_eapi():
			del self._pyeapi_node
		if self.can_ssh() and hasattr(self, 'ssh_shell'):
			self.ssh_shell.exit('logout')
			del self.ssh_shell
		super(Client, self).disconnect()

	def eapi_command(self, *args, **kwargs):
		if self.can_eapi():
			if 'encoding' in kwargs and kwargs['encoding'] == 'json':
				kwargs['strict'] = True
				eapi_output = self._pyeapi_node.enable(*args, **kwargs)[0]

				if eapi_output['encoding'] != 'json':
					raise TypeError('Enconding is not json')
				return eapi_output.get('result', [])
			else:
				kwargs['encoding'] = 'text'
				eapi_output = self._pyeapi_node.enable(*args, **kwargs)[0]

				if eapi_output['encoding'] != 'text':
					raise TypeError('Enconding is not text')
				return eapi_output.get('result', {}).get('output', '').splitlines()
		return []

	def get_config(self, source='running', section=None):
		if self.can_eapi():
			if section is not None:
				return self._pyeapi_node.get_config(
					config='{}-config'.format(source),
					params='section {}'.format(section)
				)
			return self._pyeapi_node.get_config(config='{}-config'.format(source))
		elif self.can_ssh():
			config_command = 'show {}-config'.format(source)
			if section is not None:
				config_command += ' | section {}'.format(section)
			return self.ssh_command(config_command)
		return []

	@staticmethod
	def is_arista(sys_object_id):
		if sys_object_id.startswith('1.3.6.1.4.1.30065.1'):
			return True
		return False

	def persist_configuration(self):
#		if self.in_configure_mode:
#			pass

		cli_output = self.cli_command('copy running-config startup-config')
		if cli_output[0] != 'Copy completed successfully.':
			raise base.ClientError(cli_output[0])
		return True

	def privilege_level(self):
		cli_output = self.cli_command('show privilege')
		partial_output = 'Current privilege level is '
		if not cli_output[0].startswith(partial_output):
			raise base.ClientError(cli_output)
		return int(cli_output[0][len(partial_output):])

	def software_version(self):
		if self.can_snmp():
			return self.snmp_client.os_version()
		elif self.can_eapi():
			return self.eapi_command('show version', encoding='json').get('version', None)
		elif self.can_ssh():
			return json.loads(
				''.join(self.ssh_command('show version | json'))
			).get('version', None)
		return ''

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise base.ClientError('No SSH client')
		if not hasattr(self, 'ssh_shell'):
			raise base.ClientError('No shell channel')
		shell_output = self.ssh_shell.command(*args, **kwargs)
#		config_prompt = self.ssh_shell.last_prompt.endswith('(config)#')
#		mode_mismatch = False
#		if self.in_configure_mode:
#			if not config_prompt:
#				mode_mismatch = True
#		else:
#			if config_prompt:
#				mode_mismatch = True
#		if mode_mismatch:
#			raise base.ClientError(
#				'Mistmatch between in_configure_mode [{}] and prompt [{}]'.format(
#					self.in_configure_mode,
#					self.ssh_shell.last_prompt
#				)
#			)
		return shell_output

	@staticmethod
	def vendor():
		return ('Arista', 'EOS')
