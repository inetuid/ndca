import json
import re
#
from .base import BaseClient
from .. import exception, snmp, ssh

try:
	import pyeapi
except ImportError:
	have_pyeapi = False
else:
	have_pyeapi = True


class Client(BaseClient):
	def __init__(self, *args, **kwargs):
		super(Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs('snmp_', 'ssh_', 'eapi_', **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				if not snmp_client.sysObjectID().startswith('1.3.6.1.4.1.30065.1'):
					raise exception.ClientError('Not an Arista device')
			except snmp.SNMP_Exception:
				pass
			else:
				self.snmp_client = snmp_client

		if have_pyeapi:
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

			self.ssh_shell = ssh.Shell(self.ssh_client, shell_prompt)
			self.ssh_shell.channel.set_combine_stderr(True)
			self.ssh_shell.command('terminal dont-ask')
			self.ssh_shell.command('terminal length 0')
			self.ssh_shell.command('no terminal monitor')
			self.ssh_shell.command('terminal width 160')

	def can_eapi(self):
		if hasattr(self, '_pyeapi_node'):
			return True
		return False

	def cli_command(self, *args, **kwargs):
		if self.can_eapi():
			return self.eapi_command(*args, **kwargs)
		elif self.can_ssh():
			return self.ssh_command(*args, **kwargs)
		raise exception.ClientError('No valid CLI handlers')

	def configure_via_cli(self, new_config):
		if self.can_eapi():
			try:
				config_output = self._pyeapi_node.config(new_config)
			except BaseException as error:
				print error
				return False
			else:
				for output_line in config_output:
					if output_line != {}:
						return False
			return True
		elif self.can_ssh():
			try:
				cli_output = self.ssh_command('configure terminal')
				if cli_output == []:
					self.in_configure_mode = True
				else:
					raise exception.ClientError(cli_output[0])

				for config_line in new_config:
					stripped_line = config_line.strip()
					if stripped_line in ['end', 'exit']:
						warnings.warn('Skipping ' + config_line)
						continue

					cli_output = self.ssh_command(stripped_line)
					if cli_output != []:
						raise exception.ClientError(cli_output[0])
			finally:
				cli_output = self.ssh_command('end')
				if cli_output == []:
					self.in_configure_mode = False
					return True
				else:
					raise exception.ClientError(cli_output[0])
		return False

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

	@property
	def in_configure_mode(self):
		mode_mismatch = False
		config_prompt = self.ssh_shell.last_prompt.endswith('(config)#')
		if self._in_configure_mode:
			if not config_prompt:
				mode_mismatch = True
		else:
			if config_prompt:
				mode_mismatch = True
		if mode_mismatch:
			raise exception.ClientError(
				'Mistmatch between in_configure_mode [{}] and prompt [{}]'.format(
					self._in_configure_mode,
					self.ssh_shell.last_prompt
				)
			)
		return self._in_configure_mode

	def persist_configuration(self):
#		if self.in_configure_mode:
#			pass

		cli_output = self.cli_command('copy running-config startup-config')
		if cli_output[0] != 'Copy completed successfully.':
			raise exception.ClientError(cli_output[0])
		return True

	def privilege_level(self):
		cli_output = self.cli_command('show privilege')
		if not cli_output[0].startswith('Current privilege level is '):
			raise exception.ClientError(cli_output)
		return int(cli_output[0][27:])

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
			raise exception.ClientError('No SSH client')
		if not hasattr(self, 'ssh_shell'):
			raise exception.ClientError('No shell channel')
		return self.ssh_shell.command(*args, **kwargs)

	@staticmethod
	def vendor():
		return 'Arista'


class SNMP_Client(snmp.Client):
	def os_version(self):
		re_match = re.match(
			r'Arista Networks EOS version (.+) running on an Arista Networks (.+)$',
			self.sysDescr()
		)
		if re_match is not None:
			return re_match.groups()[0]
		return None
