#yandca

Yet Another Networked Device Client Abstraction module.

Python module to abstract the connection to networked devices. Abstracts SSH, SNMP and device specific libraries such as pyeapi (Arista EOS) and ROSAPI (Mikrotik RouterBoards). If SNMP is available, will automatically detect the device and load the correct device specific driver module.

Example:

import ndca

with ndca.factory.Client(HOST_OR_IP, snmp_community=MY_COMMUNITY, username=MY_USERNAME, password=MY_PASSWORD) as ndca_client:
    print ndca.client.software_version()
