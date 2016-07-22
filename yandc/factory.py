import yandc_base as base
import yandc_snmp as snmp
from yandc_eos import Client as EOS_Client
from yandc_ios import Client as IOS_Client
from yandc_ros import Client as ROS_Client


class Client(object):
    def __new__(cls, *args, **kwargs):
        assert 'host' in kwargs, 'No host specified'

        grouped_kwargs = base.Utils.group_kwargs('snmp_', **kwargs)

        if 'snmp_' not in grouped_kwargs:
            raise base.ClientError('No SNMP details specified')

        vendor, sys_object_id = snmp.Client(
            kwargs['host'],
            **grouped_kwargs['snmp_']
        ).enterprise()

        if EOS_Client.is_arista(sys_object_id):
            return EOS_Client(*args, **kwargs)
        elif vendor == 'Cisco':
            return IOS_Client(*args, **kwargs)
        elif vendor == 'Cumulus':
            return CL_Client(*args, **kwargs)
        elif ROS_Client.is_mikrotik(sys_object_id):
            return ROS_Client(*args, **kwargs)
        else:
            raise base.ClientError('No driver for vendor')
