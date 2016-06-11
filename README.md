# ndca
Networked Device Client Abstraction

Python library to abstract the connection to networked devices. Abstracts SSH, SNMP and device specific libraries such as pyeapi (Arista EOS) and ROSAPI (Mikrotik RouterBoards). If SNMP is available, will automatically detect the device and load the correct device specific driver module.

Example:

import ndca

with ndca.factory.Client(<host_or_ip>, snmp_community=<my_community>, username=<my_username>, password=<my_password>) as ndca_client:
    print ndca_client.software_version()

