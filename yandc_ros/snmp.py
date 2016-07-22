from yandc_snmp import Client as BaseClient


class Client(BaseClient):
    def __init__(self, *args, **kwargs):
        self.oid_lookup = {
            'mtXRouterOs': (1, 3, 6, 1, 4, 1, 14988, 1, 1),
            'mtxrWireless': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 1),
            'mtxrWlStatEntry': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 1, 1, 1),
            'mtxrWlRtabEntry': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 1, 2, 1),
            'mtxrWlApEntry': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 1, 3, 1),
            'mtxrQueueSimpleEntry': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 2, 1, 1),
            'mtxrHealth': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 3),
            'mtrxLicVersion': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 4, 4, 0),
            'mtxrSystem': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 7),
            'mtxrFirmwareVersion': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 7, 4, 0),
            'mtxrNeighborTableEntry': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 11, 1, 1),
            'mtxrInterfaceStatsEntry': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 14, 1, 1),
            'mtxrPartitionEntry': (1, 3, 6, 1, 4, 1, 14988, 1, 1, 17, 1, 1),
        }
        super(Client, self).__init__(*args, **kwargs)

    def fw_version(self):
        return self.get_oid(self.oid_lookup['mtxrFirmwareVersion'])

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

        health = self._table_entries(
            self.oid_lookup['mtxrHealth'],
            table_columns,
            column_names
        )[(0, )]

        if health.get('mtxrHlActiveFan', '') == 'n/a':
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
        return self._table_entries(
            self.oid_lookup['mtxrSystem'],
            table_columns,
            column_names
        )[(0, )]

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
        return self._table_entries(
            self.oid_lookup['mtxrInterfaceStatsEntry'],
            table_columns,
            column_names
        )

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
        return self._table_entries(
            self.oid_lookup['mtxrNeighborTableEntry'],
            table_columns,
            column_names
        )

    def mtxrPartitionTable(self, column_names):
        table_columns = {
            'mtxrPartitionIndex': 1,
            'mtxrPartitionName': 2,
            'mtxrPartitionSize': 3,
            'mtxrPartitionVersion': 4,
            'mtxrPartitionActive': 5,
            'mtxrPartitionRunning': 6,
        }
        return self._table_entries(
            self.oid_lookup['mtxrPartitionEntry'],
            table_columns,
            column_names
        )

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
        return self._table_entries(
            self.oid_lookup['mtxrQueueSimpleEntry'],
            table_columns,
            column_names
        )

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
        return self._table_entries(
            self.oid_lookup['mtxrWlApEntry'],
            table_columns,
            column_names
        )

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
        return self._table_entries(
            self.oid_lookup['mtxrWlRtabEntry'],
            table_columns,
            column_names
        )

    def mtxrWlStatTable(self, column_names):
        """Get Wireless Stats"""
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
        return self._table_entries(
            self.oid_lookup['mtxrWlStatEntry'],
            table_columns,
            column_names
        )

    def os_version(self):
        """Return the Routerboard OS version"""
        return str(self.get_oid(self.oid_lookup['mtrxLicVersion']))
