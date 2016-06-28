import csv
import re
import time
import yandc

have_rosapi = False

try:
	import rosapi
except ImportError:
	pass
else:
	have_rosapi = True

class ROS_Client(yandc.BaseClient):
	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		super(ROS_Client, self).__init__(*args, **kwargs)

		grouped_kwargs = self.group_kwargs('snmp_', 'ssh_', 'rosapi_', **kwargs)

		if 'snmp_' in grouped_kwargs:
			snmp_client = SNMP_Client(kwargs['host'], **grouped_kwargs['snmp_'])
			try:
				if not snmp_client.sysObjectID().startswith('1.3.6.1.4.1.14988.1'):
					raise ValueError('Not a Mikrotik device')
			except yandc.snmp.GetError:
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

			shell_prompt = yandc.ssh.ShellPrompt(yandc.ssh.ShellPrompt.regexp_prompt(r'\[[^\@]+\@[^\]]+\] > $'))

			if 'username' in grouped_kwargs['ssh_']:
				original_username = grouped_kwargs['ssh_']['username']
				grouped_kwargs['ssh_']['username'] += '+ct0h160w'

				if self.can_snmp():
					shell_prompt.add_prompt('[' + original_username + '@' + self.snmp_client.sysName() + '] > ')

			self.ssh_client = SSH_Client(kwargs['host'], **grouped_kwargs['ssh_'])
			self.shell = SSH_Shell(self.ssh_client, shell_prompt)
			self.shell.channel.set_combine_stderr(True)

	def cli_command(self, *args, **kwargs):
		return self.ssh_command(*args, **kwargs)
		raise yandc.Client_Exception('No CLI handler')

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

	def file_exists(self, filename):
		ssh_output = self.ssh_command('/file print without-paging count-only where name="{}"'.format(filename))
		if ssh_output[0] != '0':
			return True
		return False

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
		terse_output = self.ssh_command('/interface {} print without-paging terse where name="{}"'.format(if_type, if_name))
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
				raise yandc.Client_Exception('Key not seen')
		return values_indexed

	def interface_type(self, if_name):
		terse_output = self.ssh_command('/interface print without-paging terse where name="{}"'.format(if_name))
		if terse_output[0] == '':
			return None
#		terse_output.pop()
		return self.print_to_values_structured(terse_output)[0].get('type', None)

	def interfaces(self):
		if self.can_snmp():
			return [str(v.get('ifName')) for k, v in self.snmp_client.interfaces().iteritems()]
		return [v.get('name') for v in self.print_to_values_structured(self.ssh_command('/interface print without-paging terse'))]

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
				raise yandc.Client_Exception('Key already seen - [{}]'.format(key))
			as_values[key.lstrip().rstrip()] = value.lstrip().rstrip()
		return as_values

	@staticmethod
	def Xprint_to_values_structured(print_output):
		as_values = []
		for line in print_output:
			line_parts = line.lstrip().rstrip().split()
			if not len(line_parts):
				continue
			temp = {}
			if line_parts[0].isdigit():
				temp['index'] = line_parts.pop(0)
			else:
				raise yandc.Client_Exception(line)
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
					raise yandc.Client_Exception(part)
			as_values.append(temp)
		return as_values

	@staticmethod
	def print_to_values_structured(print_output):
		as_values = []
		for line in print_output:
			line_parts = line.lstrip().rstrip().split()
			if not len(line_parts):
				continue
			temp = {
				'index': None,
				'flags': ''
			}
			if line_parts[0].isdigit():
				temp['index'] = line_parts.pop(0)
			else:
				raise yandc.Client_Exception(line)
			while True:
				part = line_parts.pop(0)
				if part.find('=') == -1:
					temp['flags'] += part
				else:
					line_parts.insert(0, part)
					break
			last_key = None
			for part in line_parts:
				if part.find('=') != -1:
					key, value = part.split('=', 1)
					temp[key] = value
					last_key = key
				elif last_key is not None:
					temp[last_key] = ' '.join([temp[last_key], part])
				else:
					raise yandc.Client_Exception(part)
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
		ssh_output = self.ssh_command('/system package print without-paging count-only where name ="{}" disabled=no'.format(package))
		if ssh_output[0] != '0':
			return True
		return False
#		terse_output = self.ssh_command('/system package print without-paging terse')
##		terse_output.pop()
#		terse_values_indexed = self.index_values(self.print_to_values_structured(terse_output), 'name')
#		if package in terse_values_indexed:
#			return terse_values_indexed[package][0].get('flags', '').find('X') == -1
#		return False

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
		try:
			time_then = time.strptime(date_time, '%b/%d/%Y %H:%M:%S')
		except (TypeError, ValueError) as e:
			return date_time
		time_now = time.time()
		return int(time_now - time.mktime(time_then))

	@staticmethod
	def vendor():
		return 'Mikrotik'

	def write_file_size_check(self, contents):
		if len(contents) > 4095:
			raise ValueError('Maximum file size exceeded')

	def write_file_contents(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.ssh_command('/file set {} contents="{}"'.format(name, contents))
		if cli_output != []:
			raise yandc.Client_Exception('Cannot set contents - [{}]'.format(cli_output[0]))
		return True

	def write_rsc_file(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.ssh_command('/system routerboard export file={}'.format(name))
		if cli_output != []:
			raise yandc.Client_Exception('Cannot create file - [{}]'.format(cli_output[0]))
		return self.write_file_contents('{}.rsc'.format(name), contents)

	def write_txt_file(self, name, contents=''):
		self.write_file_size_check(contents)
		cli_output = self.ssh_command('/file print file={}'.format(name))
		if cli_output != []:
			raise yandc.Client_Exception('Cannot create file - [{}]'.format(cli_output[0]))
		return self.write_file_contents('{}.txt'.format(name), contents)


class SNMP_Client(yandc.snmp.Client):
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


class SSH_Client(yandc.ssh.Client):
	pass


class SSH_Shell(yandc.ssh.Shell):
	def exit(self):
		return super(SSH_Shell, self).exit('/quit')

	def on_output_line(self, *args, **kwargs):
		output_line = re.sub(chr(0x1B) + r'\[9999B', '', super(SSH_Shell, self).on_output_line(*args, **kwargs))
		return output_line.lstrip('\r')
