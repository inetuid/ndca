#ndca

Networked Device Client Abstraction

Python library to abstract the connection to networked devices. Abstracts SSH, SNMP and device specific libraries such as pyeapi (Arista EOS) and ROSAPI (Mikrotik RouterBoards). If SNMP is available, will automatically detect the device and load the correct device specific driver module.

Example:

import ndca

with ndca.factory.Client(, snmp_community=, username=, password=) as ndca_client:
    print ndca.client.software_version()
