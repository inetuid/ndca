from yandc import *


class ConnectHandler(object):
	def __del__(self):
		self.disconnect()

	def __init__(self, *args, **kwargs):
		client_kwargs = {}

		if 'host' in kwargs:
			client_kwargs['host'] = kwargs['host']
		elif 'ip' in kwargs:
			client_kwargs['host'] = kwargs['ip']
		else:
			raise ValueError('Host or IP not specified')

		if 'username' in kwargs:
			client_kwargs['username'] = kwargs['username']

		if 'password' in kwargs:
			client_kwargs['password'] = kwargs['password']

		if 'port' in kwargs:
			client_kwargs['ssh_port'] = kwargs['port']

		if kwargs['device_type'] == 'arista':
			self.yandc_client = EOS_Client(**client_kwargs)
		elif kwargs['device_type'] == 'cisco_ios':
			self.yandc_client = IOS_Client(**client_kwargs)
		elif kwargs['device_type'] == 'cisco_xr':
			self.yandc_client = XR_Client(**client_kwargs)
		elif kwargs['device_type'] == 'cumulus_linux':
			self.yandc_client = CL_Client(**client_kwargs)
		elif kwargs['device_type'] == 'mikrotik':
			self.yandc_client = ROS_Client(**client_kwargs)
		else:
			raise ValueError('Device type ' + kwargs['device_type'] + ' not supported')

	def check_config_mode(self):
		return self.yandc_client.in_configure_mode()

	def config_mode(self, config_command='', *args):
		return NotImplementedError('config_mode()')

	def disconnect(self):
		if hasattr(self, 'yandc_client'):
			self.yandc_client.disconnect()
			del self.yandc_client

	def enable(self):
		return ''

	def exit_config_mode(self, exit_config, *args):
		return NotImplementedError('exit_config_mode()')

	def find_prompt(self, *args):
		return self.yandc_client.ssh_shell.last_prompt

	def send_command(self, command, *args):
		return self.yandc_client.cli_command(command)

	def send_config_from_file(self, config_file, **kwargs):
		with open(config_file, 'rb') as f:
			self.send_config_set(f.read().splitlines())

	def send_config_set(self, config_commands, *args):
		return self.yandc_client.configure_via_cli(config_commands)
