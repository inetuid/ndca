"""SSH Helper
"""

__all__ = ['SSH_Client', 'Shell', 'ShellPrompt', 'SSH_Exception', 'AuthenticationError', 'ConnectError']
__author__ = 'Matt Ryan'

import re
import socket
#
import paramiko


class SSH_Client(object):
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
#			sock.settimeout(None)
			paramiko_transport = paramiko.Transport(sock)
			paramiko_transport.connect()
		except socket.error as error:
			raise ConnectError('Could not connect to {}:{} - [{}]'.format(host, tcp_port, error.message))
		else:
			self.on_connect(paramiko_transport)

		paramiko_transport.set_keepalive(1)

		auth_types = []

#		try:
#			auth_types = paramiko_transport.auth_none(kwargs['username'])
#		except paramiko.BadAuthenticationType as auth_error:
#			auth_types = auth_error.allowed_types
#		except paramiko.SSHException as ssh_error:
#			raise SSH_Exception(ssh_error)

		try:
			paramiko_transport.auth_password(kwargs['username'], kwargs['password'])
		except paramiko.AuthenticationException as auth_error:
			raise AuthenticationError(auth_error.message)
		except paramiko.BadAuthenticationType as bad_auth_type:
			raise AuthenticationError('Auth method not supported - [{}]'.format(bad_auth_type.allowed_types))
		else:
			self.paramiko_transport = paramiko_transport

	def channel(self):
		if 'get_banner' in dir(self.paramiko_transport):
			pass
		return self.paramiko_transport.open_session()

	def disconnect(self):
		if hasattr(self, 'paramiko_transport'):
			self.paramiko_transport.close()
			del self.paramiko_transport

	def exec_command(self, command, *args):
		chan = self.channel()
		chan.set_combine_stderr(True)
		chan.exec_command(command)
		output = chan.makefile('rb')
		return [s.rstrip('\r\n') for s in output.readlines()]

	def on_connect(self, paramiko):
		pass

	def sftp_get(self, remote_path, local_path):
		sftp = paramiko.SFTPClient.from_transport(self.paramiko_transport)
		sftp.get(remote_path, local_path)
		sftp.close()

	def sftp_put(self, local_path, remote_path):
		sftp = paramiko.SFTPClient.from_transport(self.paramiko_transport)
		sftp.put(local_path, remote_path)
		sftp.close()


class Shell(object):
	def __del__(self):
		self.exit()

	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):
		self.exit()

	def __init__(self, ssh_client, shell_prompt, terminal_type='dumb'):
		assert isinstance(ssh_client, SSH_Client)
		assert isinstance(shell_prompt, ShellPrompt)

		self.ssh_client = ssh_client
		self.prompt = shell_prompt
		self.last_prompt = ''

		self.channel = ssh_client.channel()
		self.channel.settimeout(0.2)
#		self.channel.set_combine_stderr(True)
		self.channel.get_pty(terminal_type, 160, 80)
		self.channel.invoke_shell()

		banner, retries_left = self.read_until_prompt()
		if retries_left == 0:
			if len(banner) == 0:
				raise SSH_Exception('Cannot auto-detect prompt')
			timeout_prompt = banner.pop()
			self.prompt.add_prompt(timeout_prompt)
			self.command('\n', 5)
		self.on_banner(banner)

	def command(self, command, prompt_retries=40):
		send_command = command.rstrip('\r\n')
		if self.channel.send(send_command + '\r') != (len(send_command) + 1):
			raise SSH_Exception('Did not send all of command')
		if prompt_retries:
			while range(10, 0, -1):
				raw_output = self._gets()
				if raw_output != '':
					output_line = self.on_output_line(raw_output)
					if output_line != send_command:
						raise SSH_Exception('Command echo mismatch')
					break
			else:
				raise SSH_Exception('Command not echoed')
		output, retries_left = self.read_until_prompt(prompt_retries)
		if prompt_retries != 0 and retries_left == 0:
			raise SSH_Exception('Prompt not seen')
		return output

	def exit(self, exit_command='exit'):
		if hasattr(self, 'channel'):
			self.channel.send(exit_command)
			self.channel.close()
			del self.channel
		if hasattr(self, 'prompt'):
			del self.prompt
		if hasattr(self, 'ssh_client'):
			del self.ssh_client
		if hasattr(self, 'last_prompt'):
			del self.last_prompt

	def on_banner(self, banner):
		pass

	def on_output_line(self, output_line):
		return output_line.rstrip('\r\n')

	def on_prompt(self, prompt):
		pass

	def read_until_prompt(self, prompt_retries=25):
		output = []
		while prompt_retries:
			raw_output = self._gets()
			if raw_output == '':
				prompt_retries -= 1
			else :
				output_line = self.on_output_line(raw_output)
				if self.prompt.is_prompt(output_line):
					self.last_prompt = output_line
					self.on_prompt(output_line)
					break
				output.append(output_line)
		return (output, prompt_retries)

	@staticmethod
	def _getc(chan):
		if chan.recv_ready():
			return chan.recv(1)
		while True:
			if chan.exit_status_ready():
				break
			try:
				c = chan.recv(1)
			except socket.timeout:
				break
			else:
				if len(c) == 0:
					raise SSH_Exception('Channel closed during recv()')
				return c
		return None

	def _gets(self):
#		s = ''
		s = []
		while True:
			c = self._getc(self.channel)
			if c is None:
				break
#			s += c
			s.append(c)
			if c == '\n':
				break
#		return s
		return ''.join(s)


class ShellPrompt(object):
	def __init__(self, prompt=None):
		self.prompts = {}
		if prompt is not None:
			self.add_prompt(prompt)

	def add_prompt(self, prompt):
		if isinstance(prompt, basestring):
			if not prompt in self.prompts:
				self.prompts[prompt] = dict(prompt_type=basestring, prompt_value=prompt)
		elif isinstance(prompt, dict):
			if 'prompt_type' in prompt and 'prompt_value' in prompt:
				if not prompt['prompt_value'] in self.prompts:
					self.prompts[prompt['prompt_value']] = prompt
			else:
				raise ValueError('Invalid prompt specified')
		else:
			raise TypeError('Unsupported prompt type - [{}]'.format(type(prompt)))

	def is_prompt(self, candidate_prompt):
		if candidate_prompt in self.prompts and self.prompts[candidate_prompt]['prompt_type'] is basestring:
			return True

		for key, value in self.prompts.iteritems():
			if value['prompt_type'] is basestring:
				continue
				if candidate_prompt == value['prompt_value']:
					return True
			elif value['prompt_type'] == 'regexp':
				if re.match(value['prompt_regexp'], candidate_prompt):
					return True
			else:
				continue
				raise TypeError('Unsupported prompt type - [{}]'.format(value['prompt_type']))

		return False

	@staticmethod
	def regexp_prompt(re_prompt):
		return dict(prompt_type='regexp', prompt_value=re_prompt, prompt_regexp=re.compile(re_prompt))


class SSH_Exception(Exception):
	pass


class AuthenticationError(SSH_Exception):
	pass


class ConnectError(SSH_Exception):
	pass
