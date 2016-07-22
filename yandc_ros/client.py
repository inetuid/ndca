import datetime
import StringIO
#
import yandc_base as base
try:
	from .snmp import Client as SNMP_Client
except ImportError:
	HAVE_SNMP = False
else:
	from yandc_snmp.exception import SNMP_Exception
	HAVE_SNMP = True
import yandc_ssh as ssh
#
from .shell import Shell
from .utils import Utils

try:
	import rosapi
except ImportError:
	HAVE_APILIB = False
else:
	HAVE_APILIB = True


class Client(base.Client):
	def __init__(self, *args, **kwargs):
		super(Client, self).__init__(*args, **kwargs)

		grouped_kwargs = base.Utils.group_kwargs('snmp_', 'ssh_', 'rosapi_', **kwargs)

		if HAVE_SNMP and 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				sys_object_id = snmp_client.sysObjectID()
			except SNMP_Exception:
				pass
			else:
				if not self.is_mikrotik(sys_object_id):
					raise base.ClientError('Not a Mikrotik device')
				self.snmp_client = snmp_client

		self.in_safe_mode = False
		self._cli_output_cache = {}

		if HAVE_APILIB and 'rosapi_' in grouped_kwargs:
			pass

		if not self.can_rosapi():
			if 'ssh_' not in grouped_kwargs:
				grouped_kwargs['ssh_'] = {}
			if 'username' not in grouped_kwargs['ssh_'] and 'username' in kwargs:
				grouped_kwargs['ssh_']['username'] = kwargs['username']
			if 'password' not in grouped_kwargs['ssh_'] and 'password' in kwargs:
				grouped_kwargs['ssh_']['password'] = kwargs['password']

			shell_prompts = ssh.ShellPrompt(
				ssh.ShellPrompt.regexp_prompt(r'\[[^\@]+\@[^\]]+\] > $')
			)
			shell_prompts.add_prompt(
				ssh.ShellPrompt.regexp_prompt(r'\[[^\@]+\@[^\]]+\] <SAFE> $')
			)

			if 'username' in grouped_kwargs['ssh_']:
				original_username = grouped_kwargs['ssh_']['username']
				grouped_kwargs['ssh_']['username'] += '+ct0h160w'

				if self.can_snmp():
					shell_prompts.add_prompt(
						'[' + original_username + '@' + self.snmp_client.sysName() + '] > '
					)
					shell_prompts.add_prompt(
						'[' + original_username + '@' + self.snmp_client.sysName() + '] <SAFE> '
					)

			self.ssh_client = ssh.Client(kwargs['host'], **grouped_kwargs['ssh_'])

			shell_args = {
				'combine_stderr': True,
			}
			self.ssh_shell = Shell(self.ssh_client, shell_prompts, optional_args=shell_args)

			self._datetime_offset = datetime.datetime.now() - self.ros_datetime()

	def __repr__(self):
		return 'yandc_ros.Client @ {} ({})'.format(
			hex(long(id(self)) & long(0xffffffff)),
			repr(self.ssh_client)
		)

	def cli_command(self, command, *args, **kwargs):
		"""Run the specified command using the Routerboard CLI"""
		use_cache = kwargs.pop('use_cache', False)
		if use_cache:
			if command in self._cli_output_cache:
				return self._cli_output_cache[command]
		else:
			self._cli_output_cache.pop(command, None)
		ssh_output = self.ssh_command(command, *args, **kwargs)
		if use_cache:
			self._cli_output_cache[command] = ssh_output
		return ssh_output
#		raise base.ClientError('No CLI handler')

	def can_rosapi(self):
		"""Can make use of the ROSAPI package"""
		if hasattr(self, '_rosapi'):
			return True
		return False

	def configure_via_cli(self, config_commands):
		if not self.in_safe_mode:
			self.safe_mode_toggle()
		for config_line in config_commands:
			cli_output = self.cli_command(config_line, use_cache=False)
			if cli_output != []:
				raise base.ClientError(cli_output[0])
		self.safe_mode_toggle()

	def disconnect(self):
		if self.can_rosapi():
			pass
		if self.can_ssh() and hasattr(self, 'ssh_shell'):
			if self.in_safe_mode:
				self.safe_mode_toggle()
			self.ssh_shell.exit('/quit')
			del self.ssh_shell
		super(Client, self).disconnect()

	def get_config(self, source=None, section=None):
		if section is not None:
			return self.cli_command('/' + section + ' export verbose', use_cache=False)
		return self.cli_command('/export verbose', use_cache=False)

	def get_interface_config(self, if_name):
		if_type = self.interface_type(if_name)
		if if_type == 'ether':
			if_type = 'ethernet'
		elif if_type == 'pppoe-out':
			if_type = 'pppoe-client'
		return Utils.index_values(
			Utils.print_to_values_structured(
				self.cli_command('/interface {} print without-paging terse'.format(if_type))
			)
		).get(if_name)

	def interface_type(self, if_name):
		indexed_values = Utils.index_values(
			Utils.print_to_values_structured(
				self.cli_command('/interface print without-paging terse', use_cache=True)
			)
		)
		if if_name in indexed_values:
			return indexed_values[if_name][0].get('type')
		return None

	def Xinterfaces(self):
		if self.can_snmp():
			return [str(value.get('ifName')) for value in self.snmp_client.interfaces().values()]
		return [value.get('name') for value in Utils.print_to_values_structured(
			self.cli_command('/interface print without-paging terse')
		)]

	def is_directory(self, candidate_directory):
		indexed_values = Utils.index_values(
			Utils.print_to_values_structured(
				self.cli_command('/file print without-paging terse')
			)
		)
		if candidate_directory in indexed_values:
			if indexed_values[candidate_directory]['type'] == 'directory':
				return True
		return False

	def is_file(self, candidate_file):
		indexed_values = Utils.index_values(
			Utils.print_to_values_structured(
				self.cli_command('/file print without-paging terse')
			)
		)
		if candidate_file in indexed_values:
			if indexed_values[candidate_file]['type'] != 'directory':
				return True
		return False

	@staticmethod
	def is_mikrotik(sys_object_id):
		if sys_object_id.startswith('1.3.6.1.4.1.14988.1'):
			return True
		return False

	def is_slave_interface(self, if_name):
		return Utils.index_values(
			Utils.print_to_values_structured(
				self.cli_command('/interface print without-paging terse', use_cache=True)
			)
		).get(if_name, [])[0].get('flags', '').find('S') == -1

	def master_port(self, if_name):
		indexed_values = Utils.index_values(
			Utils.print_to_values_structured(
				self.cli_command('/interface ethernet print without-paging terse', use_cache=True)
			)
		)
		if if_name in indexed_values:
			master_port = indexed_values[if_name][0].get('master-port')
			if master_port is not None and master_port != 'none':
				return master_port
		return None

	def ros_datetime(self):
		system_clock = Utils.print_to_values(
			self.cli_command('/system clock print without-paging', use_cache=False)
		)
		date_string = '{} {} {}'.format(system_clock['date'], system_clock['time'], 'GMT')
		return datetime.datetime.strptime(date_string, '%b/%d/%Y %H:%M:%S %Z')

	def safe_mode_exit(self):
		if self.ssh_shell.channel.send(chr(0x04)) != 1:
			raise base.ClientError('Failed to send ^X')
		self.in_safe_mode = False

	def safe_mode_toggle(self):
		if self.ssh_shell.channel.send(chr(0x18)) != 1:
			raise base.ClientError('Failed to send ^D')
		hijack_safe_mode = \
			"Hijacking Safe Mode from someone - unroll/release/don't take it [u/r/d]: "
		self.ssh_shell.shell_prompts.add_prompt(hijack_safe_mode)
		shell_output, _ = self.ssh_shell.read_until_prompt(10)
		if self.ssh_shell.last_prompt == hijack_safe_mode:
			self.ssh_shell.channel.send('r')
			shell_output, _ = self.ssh_shell.read_until_prompt(10)
			first_line = shell_output.pop(0)
			if first_line == '114':
				pass
		if len(shell_output) < 2:
			raise base.ClientError(shell_output[0])
		if shell_output[1] == '[Safe Mode taken]':
			if self.in_safe_mode:
				raise base.ClientError('Mismatch with in_safe_mode')
			self.in_safe_mode = True
		elif shell_output[1] == '[Safe Mode released]':
			if not self.in_safe_mode:
				raise base.ClientError('Mismatch with in_safe_mode')
			self.in_safe_mode = False
		else:
			raise base.ClientError(shell_output[1])
		return self.in_safe_mode

	def software_version(self):
		if self.can_snmp():
			return self.snmp_client.os_version()
		elif self.can_ssh():
			return Utils.print_to_values(
				self.ssh_command('/system resource print without-paging')
			).get('version', '')
		return ''

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise base.ClientError('No SSH client')
		if not hasattr(self, 'ssh_shell'):
			raise base.ClientError('No shell channel')
		shell_output = self.ssh_shell.command(*args, **kwargs)
		if self.ssh_shell.last_prompt.endswith(' <SAFE> '):
			if not self.in_safe_mode:
				raise base.ClientError('Mismatch between in_safe_mode and prompt')
		return shell_output

	def system_package_enabled(self, package):
		return Utils.index_values(
			Utils.print_to_values_structured(
				self.cli_command('/system package print without-paging terse', use_cache=True)
			)
		).get(package, [])[0].get('flags', '').find('X') == -1

	def to_seconds_date_time(self, date_time):
		try:
			time_then = datetime.datetime.strptime(date_time, '%b/%d/%Y %H:%M:%S')
		except ValueError:
			return -1
		time_diff = datetime.datetime.now() + self._datetime_offset - time_then
		return int(time_diff.total_seconds())

	def upload_config(self, config, config_name):
		sftp_client = self.ssh_client.sftp_client()
		config_file = StringIO.StringIO('\r\n'.join(config))
		sftp_client.putfo(config_file, '{}.rsc'.format(config_name))
		sftp_client.close()

	@staticmethod
	def vendor():
		return ('Mikrotik', 'ROS')

	@staticmethod
	def write_file_size_check(contents):
		if len(contents) > 4095:
			raise base.FileError('Maximum file size exceeded')

	def write_file_contents(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.cli_command(
			'/file set {} contents="{}"'.format(name, contents),
			use_cache=False
		)
		if cli_output != []:
			raise base.FileError('Cannot set contents - [{}]'.format(cli_output[0]))
		return True

	def write_rsc_file(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.cli_command(
			'/system routerboard export file={}'.format(name),
			use_cache=False
		)
		if cli_output != []:
			raise base.FileError('Cannot create file - [{}]'.format(cli_output[0]))
		return self.write_file_contents('{}.rsc'.format(name), contents)

	def write_txt_file(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.cli_command('/file print file={}'.format(name), use_cache=False)
		if cli_output != []:
			raise base.FileError('Cannot create file - [{}]'.format(cli_output[0]))
		return self.write_file_contents('{}.txt'.format(name), contents)
