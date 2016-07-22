"""Simple SSH client class"""

import socket
#
import paramiko
#
from .exception import AuthenticationError, ConnectError


class Client(object):
	"""Simple SSH client class"""
	def __del__(self):
		self.disconnect()

	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.disconnect()

	def __init__(self, host, **kwargs):
		tcp_port = kwargs.get('port', 22)
		connect_timeout = kwargs.get('timeout', 10)

#		paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)
		paramiko.common.logging.basicConfig(level=paramiko.common.CRITICAL)

		try:
			sock = socket.create_connection((host, tcp_port), connect_timeout)
			paramiko_transport = paramiko.Transport(sock)
			paramiko_transport.connect()
		except socket.error as error:
			raise ConnectError(
				'Could not connect to {}:{} - [{}]'.format(host, tcp_port, error.message)
			)
		else:
			self.on_connect(paramiko_transport)

		paramiko_transport.set_keepalive(5)

#		auth_types = []

#		try:
#			auth_types = paramiko_transport.auth_none(kwargs['username'])
#		except paramiko.BadAuthenticationType as auth_error:
#			auth_types = auth_error.allowed_types
#		except paramiko.SSHException as ssh_error:
#			raise GeneralError(ssh_error)

		try:
			paramiko_transport.auth_password(kwargs['username'], kwargs['password'])
		except paramiko.AuthenticationException as auth_error:
			raise AuthenticationError(auth_error.message)
		except paramiko.BadAuthenticationType as bad_auth_type:
			raise AuthenticationError(
				'Auth method not supported - [{}]'.format(bad_auth_type.allowed_types)
			)
		else:
			self.paramiko_transport = paramiko_transport

	def __repr__(self):
		return 'ssh.Client @ {} ({})'.format(
			hex(long(id(self)) & long(0xffffffff)),
			repr(self.paramiko_transport)
	)

	def channel(self):
		"""Return a channel object"""
		if 'get_banner' in dir(self.paramiko_transport):
			pass
		return self.paramiko_transport.open_session()

	def disconnect(self):
		if hasattr(self, 'paramiko_transport'):
			if self.is_active():
				self.paramiko_transport.close()
			del self.paramiko_transport

	def exec_command(self, command, *args):
		chan = self.channel()
		chan.set_combine_stderr(True)
		chan.exec_command(command, *args)
		output = chan.makefile('rb')
		exec_output = []
		for output_line in output.readlines():
			exec_output.append(output_line.rstrip('\r\n'))
		chan.shutdown(2)
		chan.close()
		return exec_output

	def is_active(self):
		"""Is the underlying transport active"""
		if hasattr(self, 'paramiko_transport'):
			return self.paramiko_transport.is_active()
		return False

	def on_connect(self, paramiko_transport):
		"""Override to run on connect()"""
		pass

	def sftp_client(self):
		return paramiko.SFTPClient.from_transport(self.paramiko_transport)
