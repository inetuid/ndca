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

class ROS_Client(vendor_base.Client):
	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		super(ROS_Client, self).__init__(*args, **kwargs)

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
		raise vendor_base.Client_Exception('No CLI handler')

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

		super(ROS_Client, self).disconnect()

		if hasattr(self, '_software_version'):
			del self._software_version

	def get_config(self, source=None, section=None):
		if section is not None:
			return self.ssh_command('/' + section + ' export verbose')
		return self.ssh_command('/export verbose')

	def get_interface_config(self, if_name):
		if_type = self.interface_type(if_name)
		if if_type == 'ether':
			if_type = 'ethernet'
		elif if_type == 'pppoe-out':
			if_type = 'pppoe-client'
		terse_output = self.ssh_command(':put [/interface {} print terse without-paging where name="{}"]'.format(if_type, if_name))
		return self.print_to_values_structured(terse_output)

	def in_configure_mode(self, *args, **kwargs):
		return False

	def index_values(self, values, key='index'):
		values_indexed = {}
		for v in values:
			if key in v:
				if not v[key] in values_indexed:
					values_indexed[v[key]] = []
				values_indexed[v[key]].append(v)
			else:
				raise vendor_base.Client_Exception('Key not seen')
		return values_indexed

	def interface_type(self, if_name):
		terse_output = self.ssh_command('/interface print terse without-paging where name="{}"'.format(if_name))
#		terse_output.pop()
		return self.print_to_values_structured(terse_output)[0].get('type', None)

	def interfaces(self):
		if self.can_snmp():
			return [str(v.get('ifName')) for k, v in self.snmp_client.interfaces().iteritems()]
		return [v.get('name') for v in self.print_to_values_structured(self.ssh_command('/interface print terse without-paging'))]

	@staticmethod
	def print_concat(print_output):
		concat_output = []
		for line in print_output:
			if not len(line):
				continue
#			if line.startswith('       '):
			if line.startswith('   '):
				concat_output[-1] = ' '.join([concat_output[-1], line.lstrip().rstrip()])
			else:
				if line.find(';;; ') != -1:
					line = line.replace(';;; ', 'comment=')
				concat_output.append(line.lstrip().rstrip())
		return concat_output

	@staticmethod
	def print_to_values(print_output):
		as_values = {}
		for line in print_output:
			if not len(line):
				continue
			key, value = line.split(':', 1)
			if key in as_values:
				raise vendor_base.Client_Exception('Key already seen - [{}]'.format(key))
			as_values[key.lstrip().rstrip()] = value.lstrip().rstrip()
		return as_values

	@staticmethod
	def print_to_values_structured(print_output):
		as_values = []
		for line in print_output:
			line_parts = line.lstrip().rstrip().split()
			if not len(line_parts):
				continue
			temp = {}
			if line_parts[0].isdigit():
				temp['index'] = line_parts.pop(0)
			else:
				raise vendor_base.Client_Exception(line)
			if line_parts[0].find('=') == -1:
				temp['flags'] = line_parts.pop(0)
			last_key = None
			for part in line_parts:
				if part.find('=') != -1:
					key, value = part.split('=', 1)
					temp[key] = value
					last_key = key
				elif last_key is not None:
					temp[last_key] = ' '.join([temp[last_key], part])
				else:
					raise vendor_base.Client_Exception(part)
			as_values.append(temp)
		return as_values

	def software_version(self):
		if not hasattr(self, '_software_version'):
			self._software_version = None
			if self.can_snmp():
				self._software_version = self.snmp_client.os_version()
			elif self.can_ssh():
				self._software_version = self.print_to_values(self.ssh_command('/system resource print without-paging')).get('version', None)
		return self._software_version

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise ValueError('No SSH client')
		if not hasattr(self, 'shell'):
			raise ValueError('No shell channel')
		return self.shell.command(*args, **kwargs)

	def system_package_enabled(self, package):
		terse_output = self.ssh_command('/system package print terse without-paging')
#		terse_output.pop()
		terse_values_indexed = self.index_values(self.print_to_values_structured(terse_output), 'name')
		if package in terse_values_indexed:
			return terse_values_indexed[package][0].get('flags', '').find('X') == -1
		return False

	def to_seconds(self, time_format):
		seconds = minutes = hours = days = weeks = 0

		n = ''
		for c in time_format:
			if c.isdigit():
				n += c
				continue
			if c == 's':
				seconds = int(n)
			elif c == 'm':
				minutes = int(n)
			elif c == 'h':
				hours = int(n)
			elif c == 'd':
				days = int(n)
			elif c == 'w':
				weeks = int(n)
			else:
				raise ValueError('Invalid specifier - [{}]'.format(c))
			n = ''

		seconds += (minutes * 60)
		seconds += (hours * 3600)
		seconds += (days * 86400)
		seconds += (weeks * 604800)

		return seconds

	def to_seconds_date_time(self, date_time):
#jun/10/2016 16:56:03
		return date_time + '*'

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
