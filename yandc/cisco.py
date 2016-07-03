"""Cisco IOS/IOS-XR
"""

__all__ = ['IOS_Client', 'XR_Client']
__author__ = 'Matt Ryan'

import re
#
from .vendor_base import BaseClient
from . import snmp, ssh

def ios_version(s):
	re_match = re.match(r'Cisco IOS Software, .+, Version ([^\,]+),', s)
	if re_match is not None:
		return re_match.groups()[0]
	return None


class IOS_Client(BaseClient):
	def __init__(self, *args, **kwargs):
		super(IOS_Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs('snmp_', 'ssh_', **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])

			try:
				if not snmp_client.sysObjectID().startswith('1.3.6.1.4.1.9.1'):
					raise ValueError('Not a Cisco device')
			except snmp.SNMP_Exception:
				pass
			else:
				self.snmp_client = snmp_client

		if 'ssh_' in grouped_kwargs:
			self.ssh_client = SSH_Client(kwargs['host'], **grouped_kwargs['ssh_'])

			shell_prompt = ssh.ShellPrompt(ssh.ShellPrompt.regexp_prompt(r'.+[#>]$'))
			shell_prompt.add_prompt(ssh.ShellPrompt.regexp_prompt(r'.+\(config[^\)]*\)#$'))

			self.shell = Shell(self.ssh_client, shell_prompt)
			self.shell.channel.set_combine_stderr(True)
			self.shell.command('terminal length 0')
			self.shell.command('terminal no monitor')
			self.shell.command('terminal width 160')

		self._in_configure_mode = False

	def cli_command(self, *args, **kwargs):
		if self.can_ssh():
			return self.ssh_command(*args, **kwargs)
		raise Exception('No valid CLI handlers')

	def configure_via_cli(self, new_config):
		if self.can_ssh():
			try:
				cli_output = self.ssh_command('configure terminal')
				if not cli_output[0].startswith("'Enter configuration commands, one per line."):
					self._in_configure_mode = True
				else:
					raise ValueError(cli_output[0])

				for config_line in new_config:
					stripped_line = config_line.lstrip().rstrip()

					if stripped_line in ['end', 'exit']:
						continue

					cli_output = self.ssh_command(stripped_line)
					if cli_output != []:
						raise ValueError(cli_output[0])
			finally:
				cli_output = self.ssh_command('end')
				if cli_output == []:
					self._in_configure_mode = False

					return True
				else:
					raise ValueError(cli_output[0])
		return False

	def disconnect(self):
		if self.can_ssh() and hasattr(self, 'shell'):
			self.shell.exit()
			del self.shell
		super(IOS_Client, self).disconnect()

	def get_config(self, source='running', section=None):
		if self.can_ssh():
			config_command = 'show {}-config'.format(source)
			if section is not None:
				config_command += ' | section {}'.format(section)
			return self.ssh_command(config_command)
		return []

	@property
	def in_configure_mode(self):
		mode_mismatch = False
		config_prompt = self.shell.last_prompt.endswith('(config)#')
		if self._in_configure_mode:
			if not config_prompt:
				mode_mismatch = True
		else:
			if config_prompt:
				mode_mismatch = True
		if mode_mismatch:
			raise ValueError('Mistmatch between in_configure_mode [{}] and prompt [{}]'.format(self._in_configure_mode, self.shell.last_prompt))
		return self._in_configure_mode
		
	def persist_configuration(self):
 		if self.in_configure_mode:
 			pass
 
 		cli_output = self.ssh_command('write memory')
 		if cli_output[0] != 'Building configuration...' and cli_output[-1] != '[OK]':
 			raise ValueError(cli_output[0])
 
 		return True

	def privilege_level(self):
		cli_output = self.ssh_command('show privilege')
		if not cli_output[0].startswith('Current privilege level is '):
			raise ValueError(cli_output)
		return int(cli_output[0][27:])

	def software_version(self):
		if self.can_snmp():
			return self.snmp_client.os_version()
		elif self.can_ssh():
			return ios_version(self.shell.command('show version')[0])
		return ''

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise ValueError('No SSH client')
		if not hasattr(self, 'shell'):
			raise ValueError('No shell channel')
		return self.shell.command(*args, **kwargs)

	@staticmethod
	def vendor():
		return 'Cisco_IOS'


class SNMP_Client(snmp.SNMP_Client):
	def __init__(self, *args, **kwargs):
		super(SNMP_Client, self).__init__(*args, **kwargs)

	def os_version(self):
		return ios_version(self.sysDescr())


class SSH_Client(ssh.SSH_Client):
	pass


class Shell(ssh.Shell):
	def exit(self):
		return super(Shell, self).exit('logout')


try:
	import pyiosxr
except ImportError:
	have_pyiosxr = False
else:
	have_pyiosxr = True


class XR_Client(BaseClient):
	def __init__(self, *args, **kwargs):
		pass

	def disconnect(self):
		pass

	@staticmethod
	def vendor():
		return 'Cisco_XR'
