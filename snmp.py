from pysnmp.entity.rfc3413.oneliner import cmdgen
from pyasn1.type import univ
import re
import sys

def debug(func):
	def func_wrapper(*args, **kwargs):
		result = func(*args, **kwargs)
		sys.stderr.write('DEBUG: %s(%s, %s) = [%s]\n' % (func.__name__, args, kwargs, result))
		return result
	return func_wrapper

class SNMP_Exception(Exception):
	pass

class GetError(SNMP_Exception):
	pass

class Client(object):
	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		pass

	def __init__(self, host, community='public', port=161):
		self._transport = cmdgen.UdpTransportTarget((host, port), timeout=1.0, retries=1)
		self._authdata = cmdgen.CommunityData('securityIndex', community)

	def bgpIdentifier(self):
		return self.get_oid((1, 3, 6, 1, 2, 1, 15, 4, 0))

	def bgpLocalAs(self):
		return self.get_oid((1, 3, 6, 1, 2, 1, 15, 2, 0))

	def bgpPeerTable(self, column_names):
		bgp_peer_table = self._table_helper(
			(1, 3, 6, 1, 2, 1, 15, 3, 1),
			{
				'bgpPeerIdentifier': 1,
				'bgpPeerState': 2,
				'bgpPeerAdminStatus': 3,
				'bgpPeerNegotiatedVersion': 4,
				'bgpPeerLocalAddr': 5,
				'bgpPeerLocalPort': 6,
				'bgpPeerRemoteAddr': 7,
				'bgpPeerRemotePort': 8,
				'bgpPeerRemoteAs': 9,
				'bgpPeerInUpdates': 10,
				'bgpPeerOutUpdates': 11,
				'bgpPeerInTotalMessages': 12,
				'bgpPeerOutTotalMessages': 13,
				'bgpPeerLastError': 14,
				'bgpPeerFsmEstablishedTransitions': 15,
				'bgpPeerFsmEstablishedTime': 16,
				'bgpPeerConnectRetryInterval': 17,
				'bgpPeerHoldTime': 18,
				'bgpPeerKeepAlive': 19,
				'bgpPeerHoldTimeConfigured': 20,
				'bgpPeerKeepAliveConfigured': 21,
				'bgpPeerMinASOriginationInterval': 22,
				'bgpPeerMinRouteAdvertisementInterval': 23,
				'bgpPeerInUpdateElapsedTime': 24
			},
			column_names
		)

		for key, value in bgp_peer_table.iteritems():
			if 'bgpPeerState' in value:
				value['bgpPeerState'] = self.decode_bgpPeerState(value.get('bgpPeerState'))
			if 'bgpPeerAdminStatus' in value:
				value['bgpPeerAdminStatus'] = self.decode_bgpPeerAdminStatus(value.get('bgpPeerAdminStatus'))
		return bgp_peer_table

	def bgp4PathAttrTable(self, column_names):
		return self._table_helper(
			(1, 3, 6, 1, 2, 1, 15, 6, 1),
			{
				'bgp4PathAttrPeer': 1,
				'bgp4PathAttrIpAddrPrefixLen': 2,
				'bgp4PathAttrIpAddrPrefix': 3,
				'bgp4PathAttrOrigin': 4,
				'bgp4PathAttrASPathSegment': 5,
				'bgp4PathAttrNextHop': 6,
				'bgp4PathAttrMultiExitDisc': 7,
				'bgp4PathAttrLocalPref': 8,
				'bgp4PathAttrAtomicAggregate': 9,
				'bgp4PathAttrAggregatorAS': 10,
				'bgp4PathAttrAggregatorAddr': 11,
				'bgp4PathAttrCalcLocalPref': 12,
				'bgp4PathAttrBest': 13,
				'bgp4PathAttrUnknown': 14
			},
			column_names
		)

	@staticmethod
	def decode_bgpPeerAdminStatus(bgp_peeradminstatus):
		admin_status = {
			1: 'stop',
			2: 'start'
		}
		return admin_status.get(bgp_peeradminstatus, '')

	@staticmethod
	def decode_bgpPeerState(bgp_peeradminstatus):
		peer_state = {
			1: 'idle',
			2: 'connect',
			3: 'active',
			4: 'opensent',
			5: 'openconfirm',
			6: 'established'
		}
		return peer_state.get(bgp_peeradminstatus, '')

	@staticmethod
	def decode_ifAdminStatus(if_adminstatus):
		admin_status = {
			1: 'up',
			2: 'down',
			3: 'testing'
		}
		return admin_status.get(if_adminstatus, '')

	@staticmethod
	def decode_ifOperStatus(if_operstatus):
		oper_status = {
			1: 'up',
			2: 'down',
			3: 'testing',
			4: 'unknown',
			5: 'dormant',
			6: 'notPresent',
			7: 'lowerLayerDown',
		}
		return oper_status.get(if_operstatus, '')

	def disconnect(self):
		if hasattr(self, '_authdata'):
			del self._authdata
		if hasattr(self, '_transport'):
			del self._transport
		if hasattr(self, '_sysObjectID'):
			del self._sysObjectID

	def enterprise(self):
		_sysObjectID = self.sysObjectID()

		vendor = None;
		if _sysObjectID.startswith('1.3.6.1.4.1.2544.1'):
			vendor = 'Adva'
		elif _sysObjectID.startswith('1.3.6.1.4.1.30065.1'):
			vendor = 'Arista'
		elif _sysObjectID.startswith('1.3.6.1.4.1.9 1'):
			vendor = 'Cisco'
		elif _sysObjectID.startswith('1.3.6.1.4.1.40310'):
			vendor = 'Cumulus'
		elif _sysObjectID.startswith('1.3.6.1.4.1.1991.1'):
			vendor = 'Foundry'
		elif _sysObjectID.startswith('1.3.6.1.4.1.2636.1'):
			vendor = 'Juniper'
		elif _sysObjectID.startswith('1.3.6.1.4.1.14988.1'):
			vendor = 'Mikrotik'
		elif _sysObjectID.startswith('1.3.6.1.4.1.2352.1'):
			vendor = 'Redback'
		elif _sysObjectID.startswith('1.3.6.1.4.1.890.1'):
			vendor = 'Zyxel'
		return vendor, _sysObjectID

	def format_oid(self, oid):
		if isinstance(oid, str):
			return tuple(map(int, oid.lstrip('.').split('.')))
		elif isinstance(oid, (int, tuple)):
			raise TypeError
		else:
			try:
				return tuple(oid)
			except TypeError as e:
				return (int(oid), )
			raise ValueError('Cannot format OID - [{}]'.format(oid))
		
	def get_oid(self, base_oid, oid_index=None):
		snmp_oid = base_oid
		if oid_index is not None:
			if isinstance(oid_index, int):
				snmp_oid += (oid_index, )
			elif isinstance(oid_index, tuple):
				snmp_oid += oid_index
			else:
				snmp_oid += self.format_oid(oid_index)

		errorIndication, errorStatus, errorIndex, varBinds = cmdgen.CommandGenerator().getCmd(
			self._authdata,
			self._transport,
			univ.ObjectIdentifier(snmp_oid),
		)

		if errorIndication:
			raise GetError(errorIndication)
		else:
			if errorStatus:
				raise GetError(snmp_oid)
			else :
				oid, value = varBinds[0]
				if oid != snmp_oid:
					raise GetError('Mismatched SNMP OID - [{}]'.format(oid))
				return value

		return None

	def get_table_index_only(self, base_oid):
		base_oid_length = len(base_oid)
		return {(k[base_oid_length:], v) for k, v in self.walk_oids([base_oid]).iteritems()}

	def ifIndex_to_ifName(self, if_index):
		if_name = self.get_oid((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1), if_index)
		if if_name is None:
			if_name = self.get_oid((1, 3, 6, 1, 2, 1, 2, 2, 1, 1), if_index)
			if if_name is None:
				return if_index
		return if_name

	def ifTable(self, column_names):
		table_columns = {
			'ifIndex': 1,
			'ifDescr': 2,
			'ifType': 3,
			'ifMtu': 4,
			'ifSpeed': 5,
			'ifPhysAddress': 6,
			'ifAdminStatus': 7,
			'ifOperStatus': 8,
			'ifLastChange': 9,
			'ifInOctets': 10,
			'ifInUcastPkts': 11,
			'ifInNUcastPkts': 12,
			'ifInDiscards': 13,
			'ifInErrors': 14,
			'ifInUnknownProtos': 15,
			'ifOutOctets': 16,
			'ifOutUcastPkts': 17,
			'ifOutNUcastPkts': 18,
			'ifOutDiscards': 19,
			'ifOutErrors': 20,
			'ifOutQLen': 21,
			'ifSpecific': 22,
		}

		ret_ = {}
		for if_index, value in self._table_helper((1, 3, 6, 1, 2, 1, 2, 2, 1), table_columns, column_names).iteritems():
			if 'ifAdminStatus' in value:
				value['ifAdminStatus'] = self.decode_ifAdminStatus(value.get('ifAdminStatus'))
			if 'ifOperStatus' in value:
				value['ifOperStatus'] = self.decode_ifOperStatus(value.get('ifOperStatus'))
			ret_[if_index] = value
		return ret_

	def ifXTable(self, column_names):
		table_columns = {
			'ifName': 1,
			'ifInMulticastPkts': 2,
			'ifInBroadcastPkts': 3,
			'ifOutMulticastPkts': 4,
			'ifOutBroadcastPkts': 5,
			'ifHCInOctets': 6,
			'ifHCInUcastPkts': 7,
			'ifHCInMulticastPkts': 8,
			'ifHCInBroadcastPkts': 9,
			'ifHCOutOctets': 10,
			'ifHCOutUcastPkts': 11,
			'ifHCOutMulticastPkts': 12,
			'ifHCOutBroadcastPkts': 13,
			'ifLinkUpDownTrapEnable': 14,
			'ifHighSpeed': 15,
			'ifPromiscuousMode': 16,
			'ifConnectorPresent': 17,
			'ifAlias': 18,
			'ifCounterDiscontinuityTime': 19,
		}

		ret_ = {}
		for if_index, value in self._table_helper((1, 3, 6, 1, 2, 1, 31, 1, 1, 1), table_columns, column_names).iteritems():
			if 'ifLinkUpDownTrapEnable' in value:
				value['ifLinkUpDownTrapEnable'] = value.get('ifLinkUpDownTrapEnable')
			if 'ifConnectorPresent' in value:
				value['ifConnectorPresent'] = value.get('ifConnectorPresent')
			ret_[if_index] = value
		return ret_

	def inetCidrRouteTable(self, column_names):
		return self._table_helper(
			(1, 3, 6, 1, 2, 1, 4, 24, 7, 1),
			{
				'inetCidrRouteDestType': 1,
				'inetCidrRouteDest': 2,
				'inetCidrRoutePfxLen': 3,
				'inetCidrRoutePolicy': 4,
				'inetCidrRouteNextHopType': 5,
				'inetCidrRouteNextHop': 6,
				'inetCidrRouteIfIndex': 7,
				'inetCidrRouteType': 8,
				'inetCidrRouteProto': 9,
				'inetCidrRouteAge': 10,
				'inetCidrRouteNextHopAS': 11,
				'inetCidrRouteMetric1': 12,
				'inetCidrRouteMetric2': 13,
				'inetCidrRouteMetric3': 14,
				'inetCidrRouteMetric4': 15,
				'inetCidrRouteMetric5': 16,
				'inetCidrRouteStatus': 17
			},
			column_names
		)

	def interfaces(self):
		return self.ifXTable(['ifName'])
#		return self.get_table_index_only((1, 3, 6, 1, 2, 1, 2, 2, 1, 2))

	def ipNetToMediaTable(self, column_names):
		return self._table_helper(
			(1, 3, 6, 1, 2, 1, 4, 22, 1),
			{
				'ipNetToMediaIfIndex': 1,
				'ipNetToMediaPhysAddress': 2,
				'ipNetToMediaNetAddress': 3,
				'ipNetToMediaMediaType': 4,
			},
			column_names
		)

	def ipRouteTable(self, column_names):
		return self._table_helper(
			(1, 3, 6, 1, 2, 1, 4, 21, 1),
			{
				'ipRouteDest': 1,
				'ipRouteIfIndex': 2,
				'ipRouteMetric1': 3,
				'ipRouteMetric2': 4,
				'ipRouteMetric3': 5,
				'ipRouteMetric4': 6,
				'ipRouteNextHop': 7,
				'ipRouteType': 8,
				'ipRouteProto': 9,
				'ipRouteAge': 10,
				'ipRouteMask': 11,
				'ipRouteMetric5': 12,
				'ipRouteInfo': 13
			},
			column_names
		)

	def lldpLocPortTable(self, column_names):
		return self._table_helper(
			(1, 0, 8802, 1, 1, 2, 1, 3, 7, 1),
			{
				'lldpLocPortNum': 1,
				'lldpLocPortIdSubtype': 2,
				'lldpLocPortId': 3,
				'lldpLocPortDesc': 4
			},
			column_names
		)

	def lldpRemTable(self, column_names):
		return self._table_helper(
			(1, 0, 8802, 1, 1, 2, 1, 4, 1, 1),
			{
				'lldpRemTimeMark': 1,
				'lldpRemLocalPortNum': 2,
				'lldpRemIndex': 3,
				'lldpRemChassisIdSubtype': 4,
				'lldpRemChassisId': 5,
				'lldpRemPortIdSubtype': 6,
				'lldpRemPortId': 7,
				'lldpRemPortDesc': 8,
				'lldpRemSysName': 9,
				'lldpRemSysDesc': 10,
				'lldpRemSysCapSupported': 11,
				'lldpRemSysCapEnabled': 12
			},
			column_names
		)

	def set_oid(self, oid):
		raise NotImplementedError

	def sysDescr(self):
		return str(self.get_oid((1, 3, 6, 1, 2, 1, 1, 1, 0)))

	def sysObjectID(self):
		if not hasattr(self, '_sysObjectID'):
			sys_object_id = '.'.join(map(str, self.get_oid((1, 3, 6, 1, 2, 1, 1, 2, 0))))
			if len(sys_object_id) == 0:
				raise ValueError('No sysObjectID')
			self._sysObjectID = sys_object_id
		return getattr(self, '_sysObjectID', None)

	def sysORLastChange(self):
		return str(self.get_oid((1, 3, 6, 1, 2, 1, 1, 8, 0)))

	def sysORTable(self, column_names):
		return self._table_helper(
			(1, 3, 6, 1, 2, 1, 1, 9, 1),
			{
				'sysORIndex': 1,
				'sysORID': 2,
				'sysORDescr': 3,
				'sysORUpTime': 4
			},
			column_names
		)

	def sysUpTime(self):
		return int(self.get_oid((1, 3, 6, 1, 2, 1, 1, 3, 0)))

	def sysContact(self):
		return str(self.get_oid((1, 3, 6, 1, 2, 1, 1, 4, 0)))

	def sysName(self):
		return str(self.get_oid((1, 3, 6, 1, 2, 1, 1, 5, 0)))

	def sysLocation(self):
		return str(self.get_oid((1, 3, 6, 1, 2, 1, 1, 6, 0)))

	def sysServices(self):
		return self.get_oid((1, 3, 6, 1, 2, 1, 1, 7, 0))

	def walk_oids(self, oids):
		assert isinstance(oids, list)

		errorIndication, errorStatus, errorIndex, varBindTable = cmdgen.CommandGenerator().nextCmd(
			self._authdata,
			self._transport,
			*map(univ.ObjectIdentifier, oids)
		)

		if errorIndication:
			raise GetError(errorIndication)
		else:
			if errorStatus:
				raise GetError(errorStatus)
			else :
				ret_ = {}
				for varBindTableRow in varBindTable:
					for oid, value in varBindTableRow:
						if oid in ret_:
							if ret_[oid] == value:
								continue
							raise GetError('OID already seen - [{}]'.format(oid))
						ret_[oid] = value
				return ret_
		return None

	def _table_helper(self, base_oid, table_columns, column_names):
		assert isinstance(table_columns, dict)
		assert isinstance(column_names, list)

		if column_names[0] == '*':
			column_names = [k for k, v in table_columns.iteritems()]

		oid_list = []
#		for column_name in column_names:
#			if column_name in table_columns:
#				oid_list.append(base_oid + (table_columns[column_name], ))
		if len(column_names) == 1:
			oid_list.append(base_oid + (table_columns[column_names[0]], ))
		else:
			oid_list.append(base_oid)

		base_oid_length = len(base_oid)
		table_columns_reversed = dict((v, k) for k, v in table_columns.iteritems())

		ret_ = {}
		for oid, value in self.walk_oids(oid_list).iteritems():
			if oid[:base_oid_length] != base_oid:
				raise ValueError('OID out of range - [{}]'.format(oid))

			oid_parts = oid[base_oid_length:]
			if len(oid_parts) < 2:
				raise ValueError('Cannot get index')

			table_entry = oid_parts[0]
			if not table_entry in table_columns_reversed:
				raise SNMP_Exception('No column name for {}'.format(table_entry))
			table_entry = table_columns_reversed[table_entry]

			table_index = tuple(oid_parts[1:])
			if not table_index in ret_:
				ret_[table_index] = {}

			ret_[table_index][table_entry] = value
		return ret_
