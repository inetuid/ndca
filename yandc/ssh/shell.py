"""Shell class for SSH Client"""

import re
import socket
#
from .exception import GeneralError, PromptError
from .client import Client as SSH_Client


class Shell(object):
    """SSH shell class"""
    def __del__(self):
        self.exit()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.exit()

    def __init__(self, ssh_client, shell_prompts, terminal_type='dumb'):
        assert isinstance(ssh_client, SSH_Client)
        assert isinstance(shell_prompts, ShellPrompt)

        self.ssh_client = ssh_client
        self.shell_prompts = shell_prompts
        self.last_prompt = ''

        self.channel = ssh_client.channel()
        self.channel.settimeout(0.2)
#        self.channel.set_combine_stderr(True)
        self.channel.get_pty(terminal_type)
        self.channel.invoke_shell()

        banner, retries_left = self.read_until_prompt()
        if retries_left == 0:
            if len(banner) == 0:
                raise PromptError('Cannot auto-detect prompt')
            timeout_prompt = banner.pop()
            print '*{}*'.format(timeout_prompt)
            self.shell_prompts.add_prompt(timeout_prompt)
            self.command('\n', 5)
        self.on_banner(banner)

    def __repr__(self):
        return 'ssh.Shell({}) @ {}'.format(
            repr(self.ssh_client),
            hex(long(id(self)) & long(0xffffffff))
        )

    def command(self, command, prompt_retries=40):
        send_command = command.rstrip('\r\n')
        if self.channel.send(send_command + '\r') != (len(send_command) + 1):
            raise GeneralError('Did not send all of command')
        if prompt_retries:
            while range(10, 0, -1):
                raw_output = self._gets()
                if raw_output != '':
                    output_line = self.on_output_line(raw_output)
                    if output_line != send_command:
                        raise GeneralError('Command echo mismatch')
                    break
            else:
                raise GeneralError('Command not echoed')
        output, retries_left = self.read_until_prompt(prompt_retries)
        if prompt_retries != 0 and retries_left == 0:
            raise PromptError('Prompt not seen')
        return output

    def exit(self, exit_command='exit'):
        if hasattr(self, 'channel') and self.ssh_client.is_active():
            self.channel.send(exit_command)
            self.channel.close()
            print 'Deleting channel...'
            del self.channel

    def on_banner(self, banner):
        pass

    @staticmethod
    def on_output_line(output_line):
        return output_line.rstrip('\r\n')

    def on_prompt(self, prompt):
        pass

    def read_until_prompt(self, prompt_retries=25):
        output = []
        while prompt_retries:
            raw_output = self._gets()
            if raw_output == '':
                prompt_retries -= 1
            else:
                output_line = self.on_output_line(raw_output)
                if self.shell_prompts.is_prompt(output_line):
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
                    raise GeneralError('Channel closed during recv()')
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


class ShellPrompt(object):
    """Prompt handling class for Shell"""
    def __init__(self, prompt=None):
        self.prompts = {}
        if prompt is not None:
            self.add_prompt(prompt)

    def __repr__(self):
        return '{}.prompts={}'.format(type(self).__name__, repr(self.prompts))

    def add_prompt(self, prompt):
        if isinstance(prompt, basestring):
            if prompt not in self.prompts:
                self.prompts[prompt] = {
                    'prompt_type': basestring,
                    'prompt_value': prompt
                }
        elif isinstance(prompt, dict):
            if 'prompt_type' in prompt and 'prompt_value' in prompt:
                if prompt['prompt_value'] not in self.prompts:
                    self.prompts[prompt['prompt_value']] = prompt
            else:
                raise PromptError('Invalid prompt specified')
        else:
            raise PromptError('Unsupported prompt type - [{}]'.format(type(prompt)))

    def is_prompt(self, candidate_prompt):
        if candidate_prompt in self.prompts and \
                self.prompts[candidate_prompt]['prompt_type'] is basestring:
            return True
        for prompt in self.prompts.values():
            if prompt['prompt_type'] is basestring:
                continue
            elif prompt['prompt_type'] == 'regexp':
                if re.match(prompt['prompt_regexp'], candidate_prompt):
                    return True
            else:
                raise PromptError(
                    'Unsupported prompt type - [{}]'.format(prompt['prompt_type'])
                )
        return False

    @staticmethod
    def regexp_prompt(re_prompt):
        return {
            'prompt_type': 'regexp',
            'prompt_value': re_prompt,
            'prompt_regexp': re.compile(re_prompt)
        }
