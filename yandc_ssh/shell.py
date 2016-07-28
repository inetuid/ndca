"""Shell class for SSH Client"""

import socket
#
from .exception import PromptError, RecvError, ResponseError, SendError
from .client import Client
from .shell_prompt import ShellPrompt
from .utils import Utils


class Shell(object):
    """SSH shell class"""
    def __del__(self):
        self.exit()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.exit()

    def __init__(self, ssh_client, shell_prompts, optional_args=None):
        assert isinstance(ssh_client, Client)
        assert isinstance(shell_prompts, ShellPrompt)
        if optional_args is None:
            optional_args = {}

        self.ssh_client = ssh_client
        self.shell_prompts = shell_prompts
        self.last_prompt = ''
        self.recv_bufsize = optional_args.get('recv_buffer_size', 4096)
        self.line_separator = optional_args.get('line_separator', '\n')

        self.channel = ssh_client.channel()
        self.channel.settimeout(optional_args.get('timeout', 0.2))
        self.channel.set_combine_stderr(optional_args.get('combine_stderr', False))
        self.channel.get_pty(
            term=optional_args.get('terminal_type', 'dumb'),
            width=optional_args.get('terminal_width', 80),
            height=optional_args.get('terminal_height', 25)
        )
        self.channel.invoke_shell()

        banner, retries_left = self.read_until_prompt()
        if retries_left == 0:
            if len(banner) == 0:
                raise PromptError('Cannot auto-detect prompt')
            timeout_prompt = banner.pop()
            self.shell_prompts.add_prompt(timeout_prompt)
            self.command('\n', 5)
        self.on_banner(banner)

        for command in optional_args.get('initial_commands', []):
            self.command(command)

    def __repr__(self):
        return 'ssh.Shell @ {} ({})'.format(
            hex(long(id(self)) & long(0xffffffff)),
            repr(self.ssh_client)
        )

    def command(self, command, timeout_retries=40):
        send_command = command.rstrip('\r\n')
#        if self.channel.send(send_command + '\r') != (len(send_command) + 1):
#            raise SendError('Did not send all of command')
        self.channel.sendall(send_command + '\r')
#        if timeout_retries:
#            while range(10, 0, -1):
#                raw_output = self._gets()
#                if raw_output != '':
#                    output_line = self.tidy_output_line(raw_output)
#                    if output_line != send_command:
#                        raise ResponseError('Command echo mismatch')
#                    break
#            else:
#                raise ResponseError('Command not echoed')
        output, retries_left = self.read_until_prompt(timeout_retries)
        if len(output) == 0:
            raise ResponseError('Command not echoed')
        if output[0] != send_command:
            raise ResponseError('Command echo mismatch')
        output.pop(0)
        if timeout_retries != 0 and retries_left == 0:
            raise PromptError('Prompt not seen')
        return output

    def exit(self, exit_command='exit'):
        if hasattr(self, 'channel') and self.ssh_client.is_active():
            self.channel.send(exit_command)
            self.channel.shutdown(2)
            self.channel.close()
            del self.channel

    def on_banner(self, banner):
        pass

    def on_prompt(self, prompt):
        pass

    def read_until_prompt(self, timeout_retries=25):
        recv_buffer = ''
        while timeout_retries > 0:
            if self.channel.exit_status_ready():
                break
            if self.channel.recv_ready():
                recv_bytes = self.channel.recv(self.recv_bufsize)
            else:
                try:
                    recv_bytes = self.channel.recv(self.recv_bufsize)
                except socket.timeout:
                    timeout_retries -= 1
                    continue
            if len(recv_bytes) == 0:
                raise RecvError('Channel closed during recv()')
            recv_buffer += recv_bytes
            separator_position = recv_buffer.rfind(self.line_separator)
            if separator_position != -1:
                candidate_prompt = self.tidy_output_line(recv_buffer[separator_position + 1:])
                if self.shell_prompts.is_prompt(candidate_prompt):
                    self.last_prompt = candidate_prompt
                    self.on_prompt(self.last_prompt)
                    recv_buffer = recv_buffer[:separator_position]
                    break
        output = []
        for output_line in recv_buffer.split(self.line_separator):
            output.append(self.tidy_output_line(output_line))
        return (output, timeout_retries)

    def Xread_until_prompt(self, timeout_retries=25):
        output = []
        while timeout_retries > 0:
            raw_output = self._gets()
            if raw_output == '':
                timeout_retries -= 1
            else:
                output_line = self.tidy_output_line(raw_output)
                if self.shell_prompts.is_prompt(output_line):
                    self.last_prompt = output_line
                    self.on_prompt(self.last_prompt)
                    break
                output.append(output_line)
        return (output, timeout_retries)

    def tidy_output_line(self, output_line):
        return output_line.rstrip('\r')

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
                    raise RecvError('Channel closed during recv()')
                return c
        return None

    def _gets(self):
        s = []
        while True:
            c = self._getc(self.channel)
            if c is None:
                break
            s.append(c)
            if c == '\n':
                break
        return ''.join(s)
