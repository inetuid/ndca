#yandc

Yet Another Networked Device Client module.

Python module to abstract the connection to networked devices. Supports SNMP, SSH and device specific libraries such as pyeapi (Arista EOS) and ROSAPI (Mikrotik RouterBoards).
If SNMP is available, the factory class will automatically detect the device and load the correct device specific driver module.

Example:

```
import yandc.factory

with yandc.factory.Client(<HOST_OR_IP>, snmp_community=<MY_COMMUNITY>, username=<MY_USERNAME>, password=<MY_PASSWORD>) as yandc_client:
    print yandc.client.software_version()
```
