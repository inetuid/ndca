__all__ = ['EOS_Client', 'IOS_Client', 'ROS_Config', 'ROS_Client', 'ROS_Shell']

from .arista import Client as EOS_Client
from .cisco_ios import Client as IOS_Client
from .cisco_xr import Client as XR_Client
from .cumulus import Client as CL_Client
from .mikrotik import Config as ROS_Config, Client as ROS_Client, Shell as ROS_Shell
