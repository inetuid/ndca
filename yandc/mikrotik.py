"""Mikrotik ROS"""

__all__ = ['ROS_Client']
__author__ = 'Matt Ryan'

import datetime
import re
import time
#
from .vendor_base import BaseClient
from . import snmp, ssh

try:
	import rosapi
except ImportError:
	have_rosapi = False
else:
	have_rosapi = True


class ROS_Client(BaseClient):
	def __init__(self, *args, **kwargs):
		super(ROS_Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs('snmp_', 'ssh_', 'rosapi_', **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				if not snmp_client.sysObjectID().startswith('1.3.6.1.4.1.14988.1'):
					raise ValueError('Not a Mikrotik device')
			except snmp.SNMP_Exception:
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

			shell_prompt = ssh.ShellPrompt(ssh.ShellPrompt.regexp_prompt(r'\[[^\@]+\@[^\]]+\] > $'))
			shell_prompt.add_prompt(ssh.ShellPrompt.regexp_prompt(r'\[[^\@]+\@[^\]]+\] <SAFE> $'))

			if 'username' in grouped_kwargs['ssh_']:
				original_username = grouped_kwargs['ssh_']['username']
				grouped_kwargs['ssh_']['username'] += '+ct0h160w'

				if self.can_snmp():
					shell_prompt.add_prompt('[' + original_username + '@' + self.snmp_client.sysName() + '] > ')
					shell_prompt.add_prompt('[' + original_username + '@' + self.snmp_client.sysName() + '] <SAFE> ')

			self.ssh_client = SSH_Client(kwargs['host'], **grouped_kwargs['ssh_'])
			self.shell = Shell(self.ssh_client, shell_prompt)
			self.shell.channel.set_combine_stderr(True)

			self._datetime_offset = datetime.datetime.now() - self.ros_datetime()
			self._safe_mode_toggle = False

	def cli_command(self, *args, **kwargs):
		return self.ssh_command(*args, **kwargs)
		raise GeneralError('No CLI handler')

	def can_rosapi(self):
		if hasattr(self, '_rosapi'):
			return True
		return False

	def configure_via_cli(self, config_commands=[]):
		if not self._safe_mode_toggle:
			if not self.safe_mode_toggle():
				self.safe_mode_toggle()

		for config_line in config_commands:
			cli_output = self.cli_command(config_line)
			if cli_output != []:
				raise ValueError(cli_output[0])

		if self.safe_mode_toggle():
			self.safe_mode_toggle()

	def disconnect(self):
		if self.can_rosapi():
			pass
		if self.can_ssh() and hasattr(self, 'shell'):
			if self._safe_mode_toggle:
				if self.safe_mode_toggle():
					self.safe_mode_toggle()
			self.shell.exit()
			del self.shell
		super(ROS_Client, self).disconnect()

	def export_concat(self, export_config):
		concat_output = []

		export_section = None
		concat_line = []

		for line in export_config:
			if line[0] == '/':
				export_section = line
				continue
			elif line[0] == '#':
				continue
			elif line[-1:] == '\\':
				concat_line.append(line[:-1].lstrip().rstrip())
			else:
				concat_line.append(line.lstrip())
				concat_output.append('{} {}'.format(export_section, ' '.join(concat_line)))
				concat_line = []

		return concat_output

	def file_exists(self, filename):
		cli_output = self.cli_command('/file print without-paging count-only where name="{}"'.format(filename))
		if cli_output[0] != '0':
			return True
		return False

	def get_config(self, source=None, section=None):
		if section is not None:
			return self.cli_command('/' + section + ' export verbose')
		return self.cli_command('/export verbose')

	def get_interface_config(self, if_name):
		if_type = self.interface_type(if_name)
		if if_type == 'ether':
			if_type = 'ethernet'
		elif if_type == 'pppoe-out':
			if_type = 'pppoe-client'
		terse_output = self.cli_command('/interface {} print without-paging terse where name="{}"'.format(if_type, if_name))
		return self.print_to_values_structured(terse_output)

	def is_mikrotik(self, sys_object_id):
		if sys_object_id.startswith('1.3.6.1.4.1.14988.1'):
			return True
		return False

	def in_configure_mode(self, *args, **kwargs):
		return False

	@staticmethod
	def index_values(values, key='index'):
		values_indexed = {}
		for v in values:
			if key in v:
				if not v[key] in values_indexed:
					values_indexed[v[key]] = []
				values_indexed[v[key]].append(v)
			else:
				raise GeneralError('Key not seen')
		return values_indexed

	def interface_type(self, if_name):
		terse_output = self.cli_command('/interface print without-paging terse where name="{}"'.format(if_name))
		if terse_output[0] == '':
			return None
#		terse_output.pop()
		return self.print_to_values_structured(terse_output)[0].get('type', None)

	def interfaces(self):
		if self.can_snmp():
			return [str(v.get('ifName')) for k, v in self.snmp_client.interfaces().iteritems()]
		return [v.get('name') for v in self.print_to_values_structured(self.cli_command('/interface print without-paging terse'))]

	@staticmethod
	def is_cli_error(output_line):
		re_match = re.match(r'[^\(]+\(line \d+ column \d+\)', output_line)
		if re_match is not None:
			return True
		return False

	@staticmethod
	def parse_as_key_value(kv_parts):
		key_value = {}

		last_key = None
		for kv in kv_parts:
			if kv.find('=') != -1:
				k, v = kv.split('=', 1)
				if k in key_value:
					raise GeneralError('Key already seen - [{}]'.format(k))
				key_value[k] = v
				last_key = k
			elif last_key is not None:
				key_value[last_key] = ' '.join([key_value[last_key], kv])
			else:
				raise GeneralError(kv)

		return key_value

	def parse_print_as_value(self, as_values):
		kv_list = []
		for line in as_values.replace('.id=*', '\n.id=*').splitlines():
			if line == '':
				continue
			kv_list.append(self.parse_as_key_value(line.split(';')))
		return kv_list

	@staticmethod
	def print_concat(print_output):
		concat_output = []
		for line in print_output:
			if len(line) == 0:
				continue
			if line.startswith('   '):
				concat_output[-1] = ' '.join([concat_output[-1], line.lstrip().rstrip()])
			else:
				if line.find(';;; ') != -1:
					line = line.replace(';;; ', 'comment=')
				concat_output.append(line.lstrip().rstrip())
		return concat_output

	@staticmethod
	def print_to_values(print_output):
		key_value = {}
		for line in print_output:
			if len(line) == 0:
				continue
			key, value = line.split(':', 1)
			if key in key_value:
				raise GeneralError('Key already seen - [{}]'.format(key))
			key_value[key.lstrip().rstrip()] = value.lstrip().rstrip()
		return key_value

	def print_to_values_structured(self, print_output):
		kv_list = []
		for line in print_output:
			line_parts = line.lstrip().rstrip().split()
			if len(line_parts) == 0:
				continue
			if line_parts[0].isdigit():
				index_seen = line_parts.pop(0)
			else:
				raise GeneralError(line)
			flags_seen = ''
			while True:
				part = line_parts.pop(0)
				if part.find('=') == -1:
					flags_seen += part
				else:
					line_parts.insert(0, part)
					line_parts.insert(0, 'flags={}'.format(flags_seen))
					line_parts.insert(0, 'index={}'.format(index_seen))
					break
			kv_list.append(self.parse_as_key_value(line_parts))
		return kv_list

	def ros_datetime(self):
		system_clock = self.print_to_values(self.cli_command('/system clock print without-paging'))
		date_string = '{} {} {}'.format(system_clock['date'], system_clock['time'], 'GMT')
		return datetime.datetime.strptime(date_string, '%b/%d/%Y %H:%M:%S %Z')

	def safe_mode_toggle(self):
		if self.shell.channel.send(chr(0x18)) != 1:
			raise GeneralError('send()')
		shell_output, retries_left = self.shell.read_until_prompt(10)
		if shell_output[1] == '[Safe Mode taken]':
			if self._safe_mode_toggle == True:
				raise GeneralError('Mismatch with safe mode flag')
			self._safe_mode_toggle = True
		elif shell_output[1] == '[Safe Mode released]':
			if self._safe_mode_toggle == False:
				raise GeneralError('Mismatch with safe mode flag')
			self._safe_mode_toggle = False
		else:
			raise GeneralError(shell_output[1])
		return self._safe_mode_toggle

	def software_version(self):
		if self.can_snmp():
			return self.snmp_client.os_version()
		elif self.can_ssh():
			return self.print_to_values(self.ssh_command('/system resource print without-paging')).get('version', '')
		return ''

	def ssh_command(self, *args, **kwargs):
		if not self.can_ssh():
			raise ValueError('No SSH client')
		if not hasattr(self, 'shell'):
			raise ValueError('No shell channel')
		shell_output = self.shell.command(*args, **kwargs)
		if self.shell.last_prompt.endswith(' <SAFE> '):
			self._safe_mode_toggle = True
		return shell_output

	def Xsystem_package_enabled(self, package):
		cli_output = self.cli_command('/system package print without-paging count-only where name ="{}" disabled=no'.format(package))
		if cli_output[0] != '0':
			return True
		return False

	def system_package_enabled(self, package):
		if not hasattr(self, '_system_packages'):
			cli_command = '/system package print without-paging terse'
			self._system_packages = self.index_values(self.print_to_values_structured(self.cli_command(cli_command)), 'name')
		if self._system_packages.get(package)[0].get('flags', '').find('X') == -1:
			return True
		return False

	@staticmethod
	def to_seconds(time_format):
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
		try:
			time_then = datetime.datetime.strptime(date_time, '%b/%d/%Y %H:%M:%S')
		except ValueError as e:
			return -1
		time_diff = datetime.datetime.now() + self._datetime_offset - time_then
		return int(time_diff.total_seconds())

	@staticmethod
	def vendor():
		return 'Mikrotik'

	@staticmethod
	def write_file_size_check(contents):
		if len(contents) > 4095:
			raise ValueError('Maximum file size exceeded')

	def write_file_contents(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.cli_command('/file set {} contents="{}"'.format(name, contents))
		if cli_output != []:
			raise GeneralError('Cannot set contents - [{}]'.format(cli_output[0]))
		return True

	def write_rsc_file(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.cli_command('/system routerboard export file={}'.format(name))
		if cli_output != []:
			raise GeneralError('Cannot create file - [{}]'.format(cli_output[0]))
		return self.write_file_contents('{}.rsc'.format(name), contents)

	def write_txt_file(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.cli_command('/file print file={}'.format(name))
		if cli_output != []:
			raise GeneralError('Cannot create file - [{}]'.format(cli_output[0]))
		return self.write_file_contents('{}.txt'.format(name), contents)


class SNMP_Client(snmp.SNMP_Client):
	mtXRouterOs = (1, 3, 6, 1, 4, 1, 14988, 1, 1)
	mtxrWireless =  mtXRouterOs + (1, )
	mtxrWlStatTable = mtxrWireless + (1, )
	mtxrWlStatEntry = mtxrWlStatTable + (1, )
	mtxrWlRtabTable = mtxrWireless + (2, )
	mtxrWlRtabEntry = mtxrWlRtabTable + (1, )
	mtxrWlApTable = mtxrWireless + (3, )
	mtxrWlApEntry = mtxrWlApTable + (1, )
	mtxrQueues =  mtXRouterOs + (2, )
	mtxrQueueSimpleTable = mtxrQueues + (1, )
	mtxrQueueSimpleEntry = mtxrQueueSimpleTable + (1, )
	mtxrHealth =  mtXRouterOs + (3, )
	mtxrLicense =  mtXRouterOs + (4, )
	mtrxLicVersion = mtxrLicense + (4, 0)
	mtxrSystem = mtXRouterOs + (7, )
	mtxrFirmwareVersion = mtxrSystem + (4, 0)
	mtxrNeighborTable = mtXRouterOs + (11, 1)
	mtxrNeighborTableEntry = mtxrNeighborTable + (1, )
	mtxrInterfaceStatsTable = mtXRouterOs + (14, 1)
	mtxrInterfaceStatsEntry = mtxrInterfaceStatsTable + (1, )
	mtxrPartition = mtXRouterOs + (17, )
	mtxrPartitionTable = mtxrPartition + (1, )
	mtxrPartitionEntry = mtxrPartitionTable + (1, )

	def fw_version(self):
		return self.get_oid(SNMP_Client.mtxrFirmwareVersion)

	def mtxr_health(self, column_names):
		table_columns = {
			'mtxrHlCoreVoltage': 1,
			'mtxrHlThreeDotThreeVoltage': 2,
			'mtxrHlFiveVoltage': 3,
			'mtxrHlTwelveVoltage': 4,
			'mtxrHlSensorTemperature': 5,
			'mtxrHlCpuTemperature': 6,
			'mtxrHlBoardTemperature': 7,
			'mtxrHlVoltage': 8,
			'mtxrHlActiveFan': 9,
			'mtxrHlTemperature': 10,
			'mtxrHlProcessorTemperature': 11,
			'mtxrHlPower': 12,
			'mtxrHlCurrent': 13,
			'mtxrHlProcessorFrequency': 14,
			'mtxrHlPowerSupplyState': 15,
			'mtxrHlBackupPowerSupplyState': 16,
			'mtxrHlFanSpeed1': 17,
			'mtxrHlFanSpeed2': 18,
		}
		health = self._table_entries(SNMP_Client.mtxrHealth, table_columns, column_names)[(0, )]
		if health.get('mtxrHlActiveFan','') == 'n/a':
			del health['mtxrHlActiveFan']
		return health

	def mtxr_system(self, column_names):
		table_columns = {
			'mtxrSystemReboot': 1,
			'mtxrSystemUSBPowerReset': 2,
			'mtxrSystemSerialNumber': 3,
			'mtxrSystemFirmwareVersion': 4,
			'mtxrSystemNote': 5,
			'mtxrSystemBuildTime': 6,
			'mtxrSystemFirmwareUpgradeVersion': 7,
		}
		system = self._table_entries(SNMP_Client.mtxrSystem, table_columns, column_names)[(0, )]
		return system

	def mtxrInterfaceStatsTable(self, column_names):
		table_columns = {
			'mtxrInterfaceStatsIndex': 1,
			'mtxrInterfaceStatsName': 2,
			'mtxrInterfaceStatsDriverRxBytes': 11,
			'mtxrInterfaceStatsDriverRxPackets': 12,
			'mtxrInterfaceStatsDriverTxBytes': 13,
			'mtxrInterfaceStatsDriverTxPackets': 14,
			'mtxrInterfaceStatsTxRx64': 15,
			'mtxrInterfaceStatsTxRx65to127': 16,
			'mtxrInterfaceStatsTxRx128to255': 17,
			'mtxrInterfaceStatsTxRx256to511': 18,
			'mtxrInterfaceStatsTxRx512to1023': 19,
			'mtxrInterfaceStatsTxRx1024to1518': 20,
			'mtxrInterfaceStatsTxRx1519toMax': 21,
			'mtxrInterfaceStatsRxBytes': 31,
			'mtxrInterfaceStatsRxPackets': 32,
			'mtxrInterfaceStatsRxTooShort': 33,
			'mtxrInterfaceStatsRx64': 34,
			'mtxrInterfaceStatsRx64to127': 35,
			'mtxrInterfaceStatsRx128to255': 36,
			'mtxrInterfaceStatsRx256to511': 37,
			'mtxrInterfaceStatsRx512to1023': 38,
			'mtxrInterfaceStatsRx1024to1518': 39,
			'mtxrInterfaceStatsRx1519toMax': 40,
			'mtxrInterfaceStatsRxTooLong': 41,
			'mtxrInterfaceStatsRxBroadcast': 42,
			'mtxrInterfaceStatsRxPause': 43,
			'mtxrInterfaceStatsRxMulticast': 44,
			'mtxrInterfaceStatsRxFCSError': 45,
			'mtxrInterfaceStatsRxAlignError': 46,
			'mtxrInterfaceStatsRxFragement': 47,
			'mtxrInterfaceStatsRxOverflow': 48,
			'mtxrInterfaceStatsRxControl': 49,
			'mtxrInterfaceStatsRxUnknownOp': 50,
			'mtxrInterfaceStatsRxLengthError': 51,
			'mtxrInterfaceStatsRxCodeError': 52,
			'mtxrInterfaceStatsRxCarrierError': 53,
			'mtxrInterfaceStatsRxJabber': 54,
			'mtxrInterfaceStatsRxDrop': 55,
			'mtxrInterfaceStatsTxBytes': 61,
			'mtxrInterfaceStatsTxPackets': 62,
			'mtxrInterfaceStatsTxTooShort': 63,
			'mtxrInterfaceStatsTx64': 64,
			'mtxrInterfaceStatsTx64to127': 65,
			'mtxrInterfaceStatsTx128to255': 66,
			'mtxrInterfaceStatsTx256to511': 67,
			'mtxrInterfaceStatsTx512to1023': 68,
			'mtxrInterfaceStatsTx1024to1518': 69,
			'mtxrInterfaceStatsTx1519toMax': 70,
			'mtxrInterfaceStatsTxTooLong': 71,
			'mtxrInterfaceStatsTxBroadcast': 72,
			'mtxrInterfaceStatsTxPause': 73,
			'mtxrInterfaceStatsTxMulticast': 74,
			'mtxrInterfaceStatsTxUnderrun': 75,
			'mtxrInterfaceStatsTxCollision': 76,
			'mtxrInterfaceStatsTxExcessiveCollision': 77,
			'mtxrInterfaceStatsTxMultipleCollision': 78,
			'mtxrInterfaceStatsTxSingleCollision': 79,
			'mtxrInterfaceStatsTxExcessiveDeferred': 80,
			'mtxrInterfaceStatsTxDeferred': 81,
			'mtxrInterfaceStatsTxLateCollision': 82,
			'mtxrInterfaceStatsTxTotalCollision': 83,
			'mtxrInterfaceStatsTxPauseHonored': 84,
			'mtxrInterfaceStatsTxDrop': 85,
			'mtxrInterfaceStatsTxJabber': 86,
			'mtxrInterfaceStatsTxFCSError': 87,
			'mtxrInterfaceStatsTxControl': 88,
			'mtxrInterfaceStatsTxFragment': 89,
		}
		return self._table_entries(SNMP_Client.mtxrInterfaceStatsEntry, table_columns, column_names)

	def mtxrNeighborTable(self, column_names):
		table_columns = {
			'mtxrNeighborIndex': 1,
			'mtxrNeighborIpAddress': 2,
			'mtxrNeighborMacAddress': 3,
			'mtxrNeighborVersion': 4,
			'mtxrNeighborPlatform': 5,
			'mtxrNeighborIdentity': 6,
			'mtxrNeighborSoftwareID': 7,
			'mtxrNeighborInterfaceID': 8,
		}
		return self._table_entries(SNMP_Client.mtxrNeighborTableEntry, table_columns, column_names)

	def mtxrPartitionTable(self, column_names):
		table_columns = {
			'mtxrPartitionIndex': 1,
			'mtxrPartitionName': 2,
			'mtxrPartitionSize': 3,
			'mtxrPartitionVersion': 4,
			'mtxrPartitionActive': 5,
			'mtxrPartitionRunning': 6,
		}
		return self._table_entries(SNMP_Client.mtxrPartitionEntry, table_columns, column_names)

	def mtxrQueueSimpleTable(self, column_names):
		table_columns = {
			'mtxrQueueSimpleIndex': 1,
			'mtxrQueueSimpleName': 2,
			'mtxrQueueSimpleSrcAddr': 3,
			'mtxrQueueSimpleSrcMask': 4,
			'mtxrQueueSimpleDstAddr': 5,
			'mtxrQueueSimpleDstMask': 6,
			'mtxrQueueSimpleIface': 7,
			'mtxrQueueSimpleBytesIn': 8,
			'mtxrQueueSimpleBytesOut': 9,
			'mtxrQueueSimplePacketsIn': 10,
			'mtxrQueueSimplePacketsOut': 11,
			'mtxrQueueSimplePCQQueuesIn': 12,
			'mtxrQueueSimplePCQQueuesOut': 13,
			'mtxrQueueSimpleDroppedIn': 14,
			'mtxrQueueSimpleDroppedOut': 15,
		}
		return self._table_entries(SNMP_Client.mtxrQueueSimpleEntry, table_columns, column_names)

	def mtxrWlApTable(self, column_names):
		table_columns = {
			'mtxrWlApIndex': 1,
			'mtxrWlApTxRate': 2,
			'mtxrWlApRxRate': 3,
			'mtxrWlApSsid': 4,
			'mtxrWlApBssid': 5,
			'mtxrWlApClientCount': 6,
			'mtxrWlApFreq': 7,
			'mtxrWlApBand': 8,
			'mtxrWlApNoiseFloor': 9,
			'mtxrWlApOverallTxCCQ': 10,
			'mtxrWlApAuthClientCount': 11,
		}
		return self._table_entries(SNMP_Client.mtxrWlApEntry, table_columns, column_names)

	def mtxrWlRtabTable(self, column_names):
		table_columns = {
			'mtxrWlRtabAddr': 1,
			'mtxrWlRtabIface': 2,
			'mtxrWlRtabStrength': 3,
			'mtxrWlRtabTxBytes': 4,
			'mtxrWlRtabRxBytes': 5,
			'mtxrWlRtabTxPackets': 6,
			'mtxrWlRtabRxPackets': 7,
			'mtxrWlRtabTxRate': 8,
			'mtxrWlRtabRxRate': 9,
			'mtxrWlRtabRouterOSVersion': 10,
			'mtxrWlRtabUptime': 11,
			'mtxrWlRtabSignalToNoise': 12,
			'mtxrWlRtabTxStrengthCh0': 13,
			'mtxrWlRtabRxStrengthCh0': 14,
			'mtxrWlRtabTxStrengthCh1': 15,
			'mtxrWlRtabRxStrengthCh1': 16,
			'mtxrWlRtabTxStrengthCh2': 17,
			'mtxrWlRtabRxStrengthCh2': 18,
			'mtxrWlRtabTxStength': 19,
		}
		return self._table_entries(SNMP_Client.mtxrWlRtabEntry, table_columns, column_names)

	def mtxrWlStatTable(self, column_names):
		table_columns = {
			'mtxrWlStatIndex': 1,
			'mtxrWlStatTxRate': 2,
			'mtxrWlStatRxRate': 3,
			'mtxrWlStatStrength': 4,
			'mtxrWlStatSsid': 5,
			'mtxrWlStatBssid': 6,
			'mtxrWlStatFreq': 7,
			'mtxrWlStatBand': 8,
		}
		return self._table_entries(SNMP_Client.mtxrWlStatEntry, table_columns, column_names)

	def os_version(self):
		return str(self.get_oid(SNMP_Client.mtrxLicVersion))


class SSH_Client(ssh.SSH_Client):
	pass


class Shell(ssh.Shell):
	def exit(self):
		return super(Shell, self).exit('/quit')

	control_char_regexp = re.compile(r'{}\[(9999B|c)'.format(chr(0x1B)))

	def on_output_line(self, *args, **kwargs):
		output_line = re.sub(Shell.control_char_regexp, '', super(Shell, self).on_output_line(*args, **kwargs))
		return output_line.lstrip('\r')