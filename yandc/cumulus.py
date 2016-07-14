"""Cumulus Linux"""

__all__ = ['CL_Client']
__author__ = 'Matt Ryan'

import re
#
from .vendor_base import BaseClient
from . import snmp, ssh


class CL_Client(BaseClient):
	def __init__(self, *args, **kwargs):
		super(CL_Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs('snmp_', 'ssh_', **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				if not snmp_client.sysObjectID().startswith('1.3.6.1.4.1.40310'):
					raise Exception('Not a Cumulus device')
			except snmp.SNMP_Exception:
				pass
			else:
				self.snmp_client = snmp_client

		if 'ssh_' in grouped_kwargs:
			if not 'username' in grouped_kwargs['ssh_'] and 'username' in kwargs:
				grouped_kwargs['ssh_']['username'] = kwargs['username']

			if not 'password' in grouped_kwargs['ssh_'] and 'password' in kwargs:
				grouped_kwargs['ssh_']['password'] = kwargs['password']

			self.ssh_client = SSH_Client(kwargs['host'], **grouped_kwargs['ssh_'])

			shell_prompt = ssh.ShellPrompt(ssh.ShellPrompt.regexp_prompt(r'[^@]+@[^\$]+\$ '))
			if self.can_snmp() and 'username' in grouped_kwargs['ssh_']:
				shell_prompt.add_prompt(grouped_kwargs['ssh_']['username'] + '@' + self.snmp_client.sysName() + '$ ')

			self.shell = Shell(self.ssh_client, shell_prompt)

	def cli_command(self, *args, **kwargs):
		return self.ssh_command(*args, **kwargs)

	def configure_via_cli(self, new_config):
		return False

	def disconnect(self):
		if self.can_ssh() and hasattr(self, 'shell'):
			self.shell.exit()
			del self.shell
		super(CL_Client, self).disconnect()

	def get_config(self, config_source='running', config_filter=None):
		return []

	def get_interface_config(self, if_name):
		return self.ssh_command('ifquery ' + if_name)

	def in_configure_mode(self, *args, **kwargs):
		return False
		
	def software_version(self):
		if self.can_ssh():
			cli_output = self.ssh_command('lsb_release -r')
			if cli_output != []:
				return cli_output[0][8:].strip()
		return ''

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise ValueError('No SSH client')
		if not hasattr(self, 'shell'):
			raise ValueError('No shell channel')
		return self.shell.command(*args, **kwargs)

	@staticmethod
	def vendor():
		return 'Cumulus'


class SNMP_Client(snmp.SNMP_Client):
	pass


class SSH_Client(ssh.SSH_Client):
	pass


class Shell(ssh.Shell):
	def exit(self):
		return super(Shell, self).exit('logout')
