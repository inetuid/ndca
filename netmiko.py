import arista
import cisco
import cumulus
import mikrotik
import io

class ConnectHandler(object):
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
			self._config_client = arista.Client(**client_kwargs)
		elif kwargs['device_type'] == 'cisco_ios':
			self._config_client = cisco.IOS_Client(**client_kwargs)
		elif kwargs['device_type'] == 'cisco_xr':
			self._config_client = cisco.XR_Client(**client_kwargs)
		elif kwargs['device_type'] == 'cumulus_linux':
			self._config_client = cumulus.Client(**client_kwargs)
		elif kwargs['device_type'] == 'mikrotik':
			self._config_client = mikrotik.Client(**client_kwargs)
		else:
			raise ValueError('Device type ' + kwargs['device_type'] + ' not supported')

	def check_config_mode(self):
		return self._config_client.in_configure_mode()

	def config_mode(self, config_command='', *args):
		return NotImplementedError('config_mode()')

	def disconnect(self):
		self._config_client.disconnect()
		del self._config_client

	def enable(self):
		return ''

	def exit_config_mode(self, exit_config, *args):
		return NotImplementedError('exit_config_mode()')

	def find_prompt(self, *args):
		return self._config_client.shell.last_prompt()

	def send_command(self, command, *args):
		return self._config_client.cli_command(command)

	def send_config_from_file(self, config_file, **kwargs):
		with io.open(config_file) as input_file:
			pass

	def send_config_set(self, config_commands, *args):
		return self._config_client.configure_via_cli(config_commands)
