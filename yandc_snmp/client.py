from pysnmp.entity.rfc3413.oneliner import cmdgen
from pyasn1.type import univ
#
from .exception import *

__all__ = ['Client']

_Client__oid_lookup = {
    'bgp4PathAttrEntry': (1, 3, 6, 1, 2, 1, 15, 6, 1),
    'bgpPeerEntry': (1, 3, 6, 1, 2, 1, 15, 3, 1),
    'dot1dTpFdbEntry': (1, 3, 6, 1, 2, 1, 17, 4, 3, 1),
    'dot1dBasePortEntry': (1, 3, 6, 1, 2, 1, 17, 1, 4, 1),
    'dot1qTpFdbEntry': (1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1),
    'dot1qVlanCurrentEntry': (1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1),
    'entPhysicalEntry': (1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1),
    'entPhysicalMfgName': (1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 12, 1),
    'ifEntry': (1, 3, 6, 1, 2, 1, 2, 2, 1),
    'ifXEntry': (1, 3, 6, 1, 2, 1, 31, 1, 1, 1),
    'inetCidrRouteEntry': (1, 3, 6, 1, 2, 1, 4, 24, 7, 1),
    'ipAddressEntry': (1, 3, 6, 1, 2, 1, 4, 34, 1),
    'ipAddressPrefixEntry': (1, 3, 6, 1, 2, 1, 4, 32, 1),
    'ipNetToMediaEntry': (1, 3, 6, 1, 2, 1, 4, 22, 1),
    'ipRouteEntry': (1, 3, 6, 1, 2, 1, 4, 21, 1),
    'lldpLocPortEntry': (1, 0, 8802, 1, 1, 2, 1, 3, 7, 1),
    'lldpRemEntry': (1, 0, 8802, 1, 1, 2, 1, 4, 1, 1),
    'sysOREntry': (1, 3, 6, 1, 2, 1, 1, 9, 1),
}

class Client(object):
    def __del__(self):
        self.disconnect()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.disconnect()

    def __init__(self, host, community='public', port=161):
        self._transport = cmdgen.UdpTransportTarget((host, port), timeout=1.0, retries=1)
        self._authdata = cmdgen.CommunityData('securityIndex', community)

    def __repr__(self):
        return 'snmp.Client @ {} ({}, {})'.format(
            hex(long(id(self)) & long(0xffffffff)),
            repr(self._transport),
            repr(self._authdata)
        )

    def bgpIdentifier(self):
        return self.get_oid((1, 3, 6, 1, 2, 1, 15, 4, 0))

    def bgpLocalAs(self):
        return self.get_oid((1, 3, 6, 1, 2, 1, 15, 2, 0))

    def bgpPeerTable(self, column_names):
        bgp_peer_table = self._table_entries(
            __oid_lookup['bgpPeerEntry'],
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
                'bgpPeerInUpdateElapsedTime': 24,
            },
            column_names
        )
        for bgp_peer, bgp_peer_entry in bgp_peer_table.iteritems():
            if 'bgpPeerState' in bgp_peer_entry:
                bgp_peer_entry['bgpPeerState'] = self.decode_bgpPeerState(
                    bgp_peer_entry['bgpPeerState']
                )
            if 'bgpPeerAdminStatus' in bgp_peer_entry:
                bgp_peer_entry['bgpPeerAdminStatus'] = self.decode_bgpPeerAdminStatus(
                    bgp_peer_entry['bgpPeerAdminStatus']
                )
        return bgp_peer_table

    def bgp4PathAttrTable(self, column_names):
        return self._table_entries(
            __oid_lookup['bgp4PathAttrEntry'],
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
                'bgp4PathAttrUnknown': 14,
            },
            column_names
        )

    @staticmethod
    def decode_bgpPeerAdminStatus(decode_value):
        admin_status = {
            1: 'stop',
            2: 'start',
        }
        return admin_status.get(decode_value, '')

    @staticmethod
    def decode_bgpPeerState(decode_value):
        peer_state = {
            1: 'idle',
            2: 'connect',
            3: 'active',
            4: 'opensent',
            5: 'openconfirm',
            6: 'established',
        }
        return peer_state.get(decode_value, '')

    @staticmethod
    def decode_dot1qTpFdbStatus(decode_value):
        dot1qTpFdbStatus = {
            1: 'other',
            2: 'invalid',
            3: 'learned',
            4: 'self',
            5: 'mgmt',
        }
        return dot1qTpFdbStatus.get(decode_value, '')

    @staticmethod
    def decode_ifAdminStatus(decode_value):
        admin_status = {
            1: 'up',
            2: 'down',
            3: 'testing',
        }
        return admin_status.get(decode_value, '')

    @staticmethod
    def decode_ifOperStatus(decode_value):
        oper_status = {
            1: 'up',
            2: 'down',
            3: 'testing',
            4: 'unknown',
            5: 'dormant',
            6: 'notPresent',
            7: 'lowerLayerDown',
        }
        return oper_status.get(decode_value, '')

    @staticmethod
    def decode_PhysicalClass(decode_value):
        physical_class = {
            1: 'other',
            2: 'unknown',
            3: 'chassis',
            4: 'backplane',
            5: 'container',
            6: 'powerSupply',
            7: 'fan',
            8: 'sensor',
            9: 'module',
            10: 'port',
            11: 'stack',
            12: 'cpu',
        }
        return physical_class.get(decode_value, '')

    def dot1dBasePortTable(self, column_names):
        return self._table_entries(
            __oid_lookup['dot1dBasePortEntry'],
            {
                'dot1dBasePort': 1,
                'dot1dBasePortIfIndex': 2,
                'dot1dBasePortCircuit': 3,
                'dot1dBasePortBasePortDelayExceededDiscards': 4,
                'dot1dBasePortBasePortMtuExceededDiscards': 5,
            },
            column_names
        )

    def dot1dTpFdbTable(self, column_names):
        return self._table_entries(
            __oid_lookup['dot1dTpFdbEntry'],
            {
                'dot1dTpFdbAddress': 1,
                'dot1dTpFdbPort': 2,
                'dot1dTpFdbStatus': 3,
            },
            column_names
        )

    def dot1qTpFdbTable(self, column_names):
        dot1q_tp_fdb_table = self._table_entries(
            __oid_lookup['dot1qTpFdbEntry'],
            {
                'dot1qTpFdbAddress': 1,
                'dot1qTpFdbPort': 2,
                'dot1qTpFdbStatus': 3,
            },
            column_names
        )
        for _, dot1q_tp_fdb_entry in dot1q_tp_fdb_table.iteritems():
            if 'dot1qTpFdbStatus' in dot1q_tp_fdb_entry:
                dot1q_tp_fdb_entry['dot1qTpFdbStatus'] = self.decode_dot1qTpFdbStatus(
                    dot1q_tp_fdb_entry.get('dot1qTpFdbStatus')
                )
        return dot1q_tp_fdb_table

    def dot1qVlanCurrentTable(self, column_names):
        return self._table_entries(
            __oid_lookup['dot1qVlanCurrentEntry'],
            {
                'dot1qVlanTimeMark': 1,
                'dot1qVlanIndex': 2,
                'dot1qVlanFdbId': 3,
                'dot1qVlanCurrentEgressPorts': 4,
                'dot1qVlanCurrentUntaggedPorts': 5,
                'dot1qVlanStatus': 6,
                'dot1qVlanCreationTime': 7,
            },
            column_names
        )

    def disconnect(self):
        if hasattr(self, '_authdata'):
            del self._authdata
        if hasattr(self, '_transport'):
            del self._transport

    def enterprise(self):
        sys_object_id = self.sysObjectID()

        vendor = self.get_oid(__oid_lookup['entPhysicalMfgName'])
        if vendor == '':
            if sys_object_id.startswith('1.3.6.1.4.1.2544.1'):
                vendor = 'Adva'
            elif sys_object_id.startswith('1.3.6.1.4.1.30065.1'):
                vendor = 'Arista'
            elif sys_object_id.startswith('1.3.6.1.4.1.9 1'):
                vendor = 'Cisco'
            elif sys_object_id.startswith('1.3.6.1.4.1.40310'):
                vendor = 'Cumulus'
            elif sys_object_id.startswith('1.3.6.1.4.1.1991.1'):
                vendor = 'Foundry'
            elif sys_object_id.startswith('1.3.6.1.4.1.2636.1'):
                vendor = 'Juniper'
            elif sys_object_id.startswith('1.3.6.1.4.1.14988.1'):
                vendor = 'Mikrotik'
            elif sys_object_id.startswith('1.3.6.1.4.1.2352.1'):
                vendor = 'Redback'
            elif sys_object_id.startswith('1.3.6.1.4.1.890.1'):
                vendor = 'Zyxel'
        return vendor, sys_object_id

    def entPhysicalTable(self, column_names):
        return self._table_entries(
            __oid_lookup['entPhysicalEntry'],
            {
                'entPhysicalIndex': 1,
                'entPhysicalDescr': 2,
                'entPhysicalVendorType': 3,
                'entPhysicalContainedIn': 4,
                'entPhysicalClass': 5,
                'entPhysicalParentRelPos': 6,
                'entPhysicalName': 7,
                'entPhysicalHardwareRev': 8,
                'entPhysicalFirmwareRev': 9,
                'entPhysicalSoftwareRev': 10,
                'entPhysicalSerialNum': 11,
                'entPhysicalMfgName': 12,
                'entPhysicalModelName': 13,
                'entPhysicalAlias': 14,
                'entPhysicalAssetID': 15,
                'entPhysicalIsFRU': 16,
                'entPhysicalMfgDate': 17,
                'entPhysicalUris': 18,
            },
            column_names
        )

    @staticmethod
    def format_oid(oid):
        if isinstance(oid, str):
            return tuple(map(int, oid.lstrip('.').split('.')))
        elif isinstance(oid, tuple):
            return oid
        elif isinstance(oid, (int, tuple)):
            raise TypeError(oid)
        else:
            try:
                return tuple(oid)
            except TypeError:
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

        cmdGen = cmdgen.CommandGenerator()
        cmdGen.lexicographicMode = False
        cmdGen.lookupNames = False
        cmdGen.lookupValues = False

        errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
            self._authdata,
            self._transport,
            univ.ObjectIdentifier(snmp_oid),
        )

        if errorIndication:
            raise SNMP_Exception(errorIndication)
        else:
            if errorStatus:
                raise SNMP_Exception(snmp_oid)
            else:
                oid, value = varBinds[0]
                if oid != snmp_oid:
                    raise SNMP_Exception('Mismatched SNMP OID - [{}]'.format(oid))
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
        if_table = self._table_entries(
            __oid_lookup['ifEntry'],
            {
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
            },
            column_names
        )
        for if_name, if_entry in if_table.iteritems():
            if 'ifAdminStatus' in if_entry:
                if_entry['ifAdminStatus'] = self.decode_ifAdminStatus(if_entry.get('ifAdminStatus'))
            if 'ifOperStatus' in if_entry:
                if_entry['ifOperStatus'] = self.decode_ifOperStatus(if_entry.get('ifOperStatus'))
        return if_table

    def ifXTable(self, column_names):
        if_table = self._table_entries(
            __oid_lookup['ifXEntry'],
            {
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
            },
            column_names
        )
        for if_index, if_entry in if_table.iteritems():
            if 'ifLinkUpDownTrapEnable' in if_entry:
                if_entry['ifLinkUpDownTrapEnable'] = if_entry.get('ifLinkUpDownTrapEnable')
            if 'ifConnectorPresent' in if_entry:
                if_entry['ifConnectorPresent'] = if_entry.get('ifConnectorPresent')
        return if_table

    def inetCidrRouteTable(self, column_names):
        return self._table_entries(
            __oid_lookup['inetCidrRouteEntry'],
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
                'inetCidrRouteStatus': 17,
            },
            column_names
        )

    def interfaces(self):
        return self.ifXTable(['ifName'])
#        return self.get_table_index_only((1, 3, 6, 1, 2, 1, 2, 2, 1, 2))

    def ipAddressPrefixTable(self, column_names):
        return self._table_entries(
            __oid_lookup['ipAddressPrefixEntry'],
            {
                'ipAddressPrefixIfIndex': 1,
                'ipAddressPrefixType': 2,
                'ipAddressPrefixPrefix': 3,
                'ipAddressPrefixLength': 4,
                'ipAddressPrefixOrigin': 5,
                'ipAddressPrefixOnLinkFlag': 6,
                'ipAddressPrefixAutonomousFlag': 7,
                'ipAddressPrefixAdvPreferredLifetime': 8,
                'ipAddressPrefixAdvValidLifetime': 9,
            },
            column_names
        )

    def ipAddressTable(self, column_names):
        return self._table_entries(
            __oid_lookup['ipAddressEntry'],
            {
                'ipAddressAddrType': 1,
                'ipAddressAddr': 2,
                'ipAddressIfIndex': 3,
                'ipAddressType': 4,
                'ipAddressPrefix': 5,
                'ipAddressOrigin': 6,
                'ipAddressStatus': 7,
                'ipAddressCreated': 8,
                'ipAddressLastChanged': 9,
                'ipAddressRowStatus': 10,
                'ipAddressStorageType': 11,
            },
            column_names
        )

    def ipNetToMediaTable(self, column_names):
        return self._table_entries(
            __oid_lookup['ipNetToMediaEntry'],
            {
                'ipNetToMediaIfIndex': 1,
                'ipNetToMediaPhysAddress': 2,
                'ipNetToMediaNetAddress': 3,
                'ipNetToMediaMediaType': 4,
            },
            column_names
        )

    def ipRouteTable(self, column_names):
        return self._table_entries(
            __oid_lookup['ipRouteEntry'],
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
                'ipRouteInfo': 13,
            },
            column_names
        )

    def lldpLocPortTable(self, column_names):
        return self._table_entries(
            __oid_lookup['lldpLocPortEntry'],
            {
                'lldpLocPortNum': 1,
                'lldpLocPortIdSubtype': 2,
                'lldpLocPortId': 3,
                'lldpLocPortDesc': 4,
            },
            column_names
        )

    def lldpRemTable(self, column_names):
        return self._table_entries(
            __oid_lookup['lldpRemEntry'],
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
                'lldpRemSysCapEnabled': 12,
            },
            column_names
        )

    def set_oid(self, oid):
        raise NotImplementedError

    def sysDescr(self):
        return str(self.get_oid((1, 3, 6, 1, 2, 1, 1, 1, 0)))

    def sysObjectID(self):
        sys_object_id = '.'.join(map(str, self.get_oid((1, 3, 6, 1, 2, 1, 1, 2, 0))))
        if len(sys_object_id) == 0:
            raise ValueError('No sysObjectID')
        return sys_object_id

    def sysORLastChange(self):
        return str(self.get_oid((1, 3, 6, 1, 2, 1, 1, 8, 0)))

    def sysORTable(self, column_names):
        return self._table_entries(
            __oid_lookup['sysOREntry'],
            {
                'sysORIndex': 1,
                'sysORID': 2,
                'sysORDescr': 3,
                'sysORUpTime': 4,
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

        cmdGen = cmdgen.CommandGenerator()
        cmdGen.lexicographicMode = False
        cmdGen.lookupNames = False
        cmdGen.lookupValues = False

        errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
            self._authdata,
            self._transport,
            *map(univ.ObjectIdentifier, oids)
        )

        if errorIndication:
            raise SNMP_Exception(errorIndication)
        else:
            if errorStatus:
                raise SNMP_Exception(errorStatus)
            else:
                ret_ = {}
                for varBindTableRow in varBindTable:
                    for oid, value in varBindTableRow:
                        if oid in ret_:
                            if ret_[oid] == value:
                                continue
                            raise SNMP_Exception('OID already seen - [{}]'.format(oid))
                        ret_[oid] = value
                return ret_
        return None

    def _table_entries(self, entry_oid, table_columns, column_names):
        assert isinstance(table_columns, dict)
        assert isinstance(column_names, list)

        if column_names[0] == '*':
            column_names = table_columns.keys()

        oid_list = []
        for column_name in column_names:
            if column_name in table_columns:
#                oid_list.append(entry_oid + (table_columns[column_name], ))
                pass
            else:
                raise ValueError('Invalid column - [{}]'.format(column_name))

        if len(column_names) == 1:
            oid_list.append(entry_oid + (table_columns[column_names[0]], ))
        else:
            oid_list.append(entry_oid)

        entry_oid_length = len(entry_oid)
        table_columns_reversed = dict((v, k) for k, v in table_columns.iteritems())

        table_entries = {}
        for oid, value in self.walk_oids(oid_list).iteritems():
            if oid[:entry_oid_length] != entry_oid:
                raise ValueError('OID out of range - [{}]'.format(oid))

            oid_parts = oid[entry_oid_length:]
            if len(oid_parts) < 2:
                raise ValueError('Cannot get index')

            table_entry = oid_parts[0]
            if table_entry not in table_columns_reversed:
                raise SNMP_Exception('No column name for {}'.format(table_entry))
            table_entry = table_columns_reversed[table_entry]

            table_index = tuple(oid_parts[1:])
            if table_index not in table_entries:
                table_entries[table_index] = {}

            table_entries[table_index][table_entry] = value
        return table_entries
